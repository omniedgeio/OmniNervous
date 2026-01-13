use std::collections::HashMap;
use crate::noise::NoiseSession;
use anyhow::Result;

pub enum SessionState {
    Handshaking(NoiseSession),
    Active(snow::StatelessTransportState),
}

pub struct SessionManager {
    sessions: HashMap<u32, SessionState>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    pub fn create_session(&mut self, session_id: u32, state: SessionState) {
        self.sessions.insert(session_id, state);
    }

    pub fn get_session_mut(&mut self, session_id: u32) -> Option<&mut SessionState> {
        self.sessions.get_mut(&session_id)
    }

    /// Advance the handshake for a given session.
    pub fn advance_handshake(&mut self, session_id: u32, message: &[u8]) -> Result<Option<Vec<u8>>> {
        if let Some(SessionState::Handshaking(ref mut session)) = self.sessions.get_mut(&session_id) {
            let response = session.process_handshake(message)?;
            Ok(Some(response))
        } else {
            Ok(None)
        }
    }

    /// Finalize a handshake and move the session to Active state.
    pub fn finalize_session(&mut self, session_id: u32) -> Result<bool> {
        if let Some(state) = self.sessions.remove(&session_id) {
            if let SessionState::Handshaking(session) = state {
                if session.is_handshake_finished() {
                    let transport = session.into_transport()?;
                    self.sessions.insert(session_id, SessionState::Active(transport));
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
}
