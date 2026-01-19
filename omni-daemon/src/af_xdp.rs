use xsk_rs::{
    config::{SocketConfig, UmemConfig},
    umem::Umem,
    socket::Socket,
};
use anyhow::{Result, Context};
#[cfg(target_os = "linux")]
use aya::maps::XskMap;
use std::num::NonZeroU32;
use std::os::unix::io::AsRawFd;

pub struct AfXdpSocket {
    pub tx_q: xsk_rs::socket::TxQueue,
    pub rx_q: xsk_rs::socket::RxQueue,
    pub fq: xsk_rs::umem::FillQueue,
    pub cq: xsk_rs::umem::CompQueue,
    pub umem: Umem,
    pub tx_frames: Vec<xsk_rs::umem::frame::FrameDesc>,
}

impl AfXdpSocket {
    #[cfg(target_os = "linux")]
    pub fn new(ifname: &str, queue_id: u32, xsk_map: &mut XskMap<aya::maps::MapData>) -> Result<Self> {
        // 1. Configure UMEM and Socket
        let umem_config = UmemConfig::default();
        let socket_config = SocketConfig::default();
        let frames_count = NonZeroU32::new(4096).unwrap();

        // xsk-rs 0.8.x direct construction
        let (umem, frame_descs) = Umem::new(umem_config, frames_count, false)
            .context("Failed to build AF_XDP Umem")?;

        // Socket::new(config, &umem, &if_name, queue_id)
        let (tx_q, rx_q, fq_cq) = unsafe {
            Socket::new(
                socket_config,
                &umem,
                &ifname.parse().context("Invalid ifname")?,
                queue_id,
            )
        }.context("Failed to build AF_XDP Socket")?;

        let (mut fq, cq) = fq_cq.context("Fill/Comp queues missing")?;
        
        // 2. Register socket FD in eBPF XSK_MAP
        let fd = tx_q.fd().as_raw_fd();
        
        xsk_map.set(queue_id, fd, 0)
            .context("Failed to register AF_XDP FD in BPF map")?;

        // 3. Initial Fill Queue seeding
        let mut frame_descs = frame_descs;
        let tx_frames = frame_descs.split_off(2048);
        
        unsafe { fq.produce(&frame_descs) };

        log::info!("🚀 AF_XDP Zero-Copy enabled on {} (RX: {}, TX: {})", ifname, frame_descs.len(), tx_frames.len());
        
        Ok(Self { tx_q, rx_q, fq, cq, umem, tx_frames })
    }

    /// Process packets from the RX queue in a batch without intermediate copying.
    /// The closure `f` receives the raw packet data directly from the UMEM.
    pub fn recv_batch<F>(&mut self, max_count: usize, mut f: F) -> Result<usize> 
    where F: FnMut(&[u8]) 
    {
        use xsk_rs::umem::frame::FrameDesc;
        let mut descs = [FrameDesc::default(); 16];
        let count_to_consume = max_count.min(16);
        
        // 1. Consume from RX queue
        let count = unsafe { self.rx_q.consume(&mut descs[..count_to_consume]) };
        if count == 0 {
            return Ok(0);
        }

        for i in 0..count {
            let data = unsafe { self.umem.data(&descs[i]) };
            f(&*data);
        }

        // 2. Release to Fill queue
        unsafe { self.fq.produce(&descs[..count]) };
        
        Ok(count)
    }

    /// Prepare and push packets to the TX queue in a batch.
    /// The closure `f` is responsible for writing data into the UMEM frame and returning the length.
    pub fn send_batch<F>(&mut self, max_count: usize, mut f: F) -> Result<usize>
    where F: FnMut(&mut [u8]) -> Option<usize>
    {
        use xsk_rs::umem::frame::FrameDesc;
        
        // 1. Recycle completed frames
        let mut completed_descs = [FrameDesc::default(); 16];
        let completed = unsafe { self.cq.consume(&mut completed_descs) };
        for i in 0..completed {
            self.tx_frames.push(completed_descs[i]);
        }
        
        let count_to_send = max_count.min(16).min(self.tx_frames.len());
        if count_to_send == 0 {
            return Ok(0);
        }

        let mut descs = [FrameDesc::default(); 16];
        let mut actual_count = 0;

        for _i in 0..count_to_send {
            if let Some(mut frame) = self.tx_frames.pop() {
                let mut data = unsafe { self.umem.data_mut(&mut frame) };
                
                if let Some(len) = f(&mut *data) {
                    // Update the length in the native descriptor (xdp_desc)
                    unsafe {
                        let desc_ptr = &mut frame as *mut _ as *mut u64;
                        let len_ptr = (desc_ptr as *mut u8).add(8) as *mut u32;
                        *len_ptr = len as u32;
                    }
                    descs[actual_count] = frame;
                    actual_count += 1;
                } else {
                    // If closure returns None, we put the frame back
                    self.tx_frames.push(frame);
                }
            }
        }

        // 2. Produce to TX queue
        if actual_count > 0 {
            Ok(unsafe { self.tx_q.produce(&descs[..actual_count]) })
        } else {
            Ok(0)
        }
    }

    /// Push packets already in memory (fallback or small buffers)
    pub fn send_burst(&mut self, packets: &[&[u8]]) -> Result<usize> {
        self.send_batch(packets.len(), |buf| {
            if packets.is_empty() { return None; }
            // This is still a copy, but it's the single unavoidable copy between Umems
            let p = packets[0]; // Simplified for now as we take one at a time in the current loop
            let len = p.len().min(buf.len());
            buf[..len].copy_from_slice(&p[..len]);
            Some(len)
        })
    }

    /// Get the raw FD for waiting with tokio
    pub fn fd(&self) -> i32 {
        self.tx_q.fd().as_raw_fd()
    }
}
