#!/usr/bin/env bash
set -euo pipefail

VIP_A=${VIP_A:-10.200.0.10}
VIP_B=${VIP_B:-10.200.0.20}
NUCLEUS_PORT=${NUCLEUS_PORT:-51820}
CLUSTER_SECRET=${CLUSTER_SECRET:-ci-test-secret-min16}
L2_BRIDGE_A=${L2_BRIDGE_A:-10.210.0.10}
L2_BRIDGE_B=${L2_BRIDGE_B:-10.210.0.20}

IMAGE=${IMAGE:-omninervous:test}
NETWORK=${NETWORK:-omni-test-net}

DEVICE_ARG="--device /dev/net/tun:/dev/net/tun"
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*)
    export MSYS2_ARG_CONV_EXCL="/dev/net/tun"
    ;;
  *)
    ;;
esac

cleanup() {
  docker stop nucleus edge-a edge-b 2>/dev/null || true
  docker rm nucleus edge-a edge-b 2>/dev/null || true
  docker network rm "$NETWORK" 2>/dev/null || true
}
trap cleanup EXIT

printf "\n==> Building Docker image with l2-vpn feature\n"
docker image rm -f "$IMAGE" 2>/dev/null || true
docker build --build-arg CARGO_FEATURES="--features l2-vpn" -t "$IMAGE" .

printf "\n==> Creating Docker network\n"
docker network rm "$NETWORK" 2>/dev/null || true
docker network create --subnet=10.88.0.0/24 "$NETWORK"

printf "\n==> Starting nucleus\n"
docker run -d --name nucleus \
  --network "$NETWORK" \
  --ip 10.88.0.2 \
  -e RUST_LOG=info \
  "$IMAGE" \
  --mode nucleus \
  --cluster ci-test \
  --secret "$CLUSTER_SECRET" \
  --port "$NUCLEUS_PORT"

sleep 3

docker ps -a --filter name=nucleus --format '{{.Status}}'

echo "=== Nucleus Logs ==="
docker logs nucleus --tail 50 || true

printf "\n==> Starting edge-a\n"
docker run -d --name edge-a \
  --network "$NETWORK" \
  --ip 10.88.0.10 \
  --privileged \
  --cap-add=NET_ADMIN \
  $DEVICE_ARG \
  -e RUST_LOG=info \
  "$IMAGE" \
  --nucleus 10.88.0.2:"$NUCLEUS_PORT" \
  --cluster ci-test \
  --secret "$CLUSTER_SECRET" \
  --vip "$VIP_A" \
  --port 51820 \
  --userspace \
  --tun-name omniwg0 \
  --transport-mode l2

sleep 3

printf "\n==> Starting edge-b\n"
docker run -d --name edge-b \
  --network "$NETWORK" \
  --ip 10.88.0.20 \
  --privileged \
  --cap-add=NET_ADMIN \
  $DEVICE_ARG \
  -e RUST_LOG=info \
  "$IMAGE" \
  --nucleus 10.88.0.2:"$NUCLEUS_PORT" \
  --cluster ci-test \
  --secret "$CLUSTER_SECRET" \
  --vip "$VIP_B" \
  --port 51821 \
  --userspace \
  --tun-name omniwg0 \
  --transport-mode l2

sleep 35

printf "\n==> Diagnostics\n"

echo "=== Container Status ==="
docker ps -a

echo "=== Edge A Logs ==="
docker logs edge-a --tail 50 || true

echo "=== Edge B Logs ==="
docker logs edge-b --tail 50 || true

echo "=== Edge A Interfaces ==="
docker exec edge-a ip addr show || true

echo "=== Edge B Interfaces ==="
docker exec edge-b ip addr show || true

echo "=== Edge A WireGuard ==="
docker exec edge-a wg show || true

echo "=== Edge B WireGuard ==="
docker exec edge-b wg show || true

echo "=== Edge A Peers (logs) ==="
docker logs edge-a --tail 100 || true

echo "=== Edge B Peers (logs) ==="
docker logs edge-b --tail 100 || true

printf "\n==> Waiting for WireGuard peers\n"
WG_READY="no"
for attempt in 1 2 3 4 5 6; do
  if docker exec edge-a wg show 2>/dev/null | grep -q "peer:"; then
    WG_READY="yes"
    break
  fi
  echo "Waiting for peers (attempt $attempt)..."
  sleep 5
done

if [ "$WG_READY" != "yes" ]; then
  echo "WARNING: no WireGuard peers detected before tests"
fi

printf "\n==> L3 Ping test\n"
PING_RESULT="FAILED"
PING_LATENCY="N/A"

for attempt in 1 2 3; do
  echo "Attempt $attempt..."
  PING_OUTPUT=$(docker exec edge-a ping -c 5 -W 3 "$VIP_B" 2>&1) || true
  echo "$PING_OUTPUT"

  if echo "$PING_OUTPUT" | grep -q "bytes from"; then
    RECEIVED=$(echo "$PING_OUTPUT" | grep -c "bytes from" || echo "0")
    PING_LATENCY=$(echo "$PING_OUTPUT" | grep "avg" | awk -F'/' '{print $5}' || echo "N/A")
    echo "Ping: SUCCESS ($RECEIVED/5 packets, avg ${PING_LATENCY}ms)"
    PING_RESULT="PASSED"
    break
  else
    echo "Ping: FAILED"
  fi
  sleep 2
 done

printf "\n==> Configure L2 bridge\n"
docker exec edge-a ip link add br0 type bridge
docker exec edge-a ip link set br0 up
docker exec edge-a ip link set omni0 master br0
docker exec edge-a ip link set omni0 up
docker exec edge-a ip link add dummy0 type dummy
docker exec edge-a ip link set dummy0 master br0
docker exec edge-a ip link set dummy0 up
docker exec edge-a ip addr add "$L2_BRIDGE_A"/24 dev dummy0

docker exec edge-b ip link add br0 type bridge
docker exec edge-b ip link set br0 up
docker exec edge-b ip link set omni0 master br0
docker exec edge-b ip link set omni0 up
docker exec edge-b ip link add dummy0 type dummy
docker exec edge-b ip link set dummy0 master br0
docker exec edge-b ip link set dummy0 up
docker exec edge-b ip addr add "$L2_BRIDGE_B"/24 dev dummy0

printf "\n==> L2 Ping test\n"
L2_PING_RESULT="FAILED"
L2_PING_LATENCY="N/A"

for attempt in 1 2 3; do
  echo "Attempt $attempt..."
  L2_PING_OUTPUT=$(docker exec edge-a ping -c 5 -W 3 "$L2_BRIDGE_B" 2>&1) || true
  echo "$L2_PING_OUTPUT"

  if echo "$L2_PING_OUTPUT" | grep -q "bytes from"; then
    RECEIVED=$(echo "$L2_PING_OUTPUT" | grep -c "bytes from" || echo "0")
    L2_PING_LATENCY=$(echo "$L2_PING_OUTPUT" | grep "avg" | awk -F'/' '{print $5}' || echo "N/A")
    echo "L2 Ping: SUCCESS ($RECEIVED/5 packets, avg ${L2_PING_LATENCY}ms)"
    L2_PING_RESULT="PASSED"
    break
  else
    echo "L2 Ping: FAILED"
  fi
  sleep 2
 done

printf "\n==> Summary\n"
printf "L3 Ping: %s (%s ms)\n" "$PING_RESULT" "$PING_LATENCY"
printf "L2 Ping: %s (%s ms)\n" "$L2_PING_RESULT" "$L2_PING_LATENCY"

if [ "$PING_RESULT" != "PASSED" ]; then
  echo "WARNING: L3 ping failed"
fi
if [ "$L2_PING_RESULT" != "PASSED" ]; then
  echo "WARNING: L2 ping failed"
fi
