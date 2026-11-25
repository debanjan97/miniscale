#!/usr/bin/env bash
# Layer 3: real NAT traversal using Linux network namespaces (needs root / CAP_NET_ADMIN).
#
#   h1 (10.1.0.2) ── r1 [NAT] ──┐
#                               ├── "internet" 203.0.113.0/24: derp + coord at .1
#   h2 (10.2.0.2) ── r2 [NAT] ──┘
#
#   ./nat_test.sh easy   both routers use plain MASQUERADE (port-preserving)  -> expect direct
#   ./nat_test.sh hard   both use MASQUERADE --random-fully (a new port per destination,
#                        i.e. "symmetric" NAT, so STUN's answer is useless)     -> expect derp
set -euo pipefail
MODE=${1:-easy}
BIN=$(mktemp -d)/miniscale
go build -o "$BIN" .

cleanup() { for ns in inet r1 r2 h1 h2; do { ip netns pids $ns | xargs -r kill; ip netns del $ns; } 2>/dev/null || true; done; }
trap cleanup EXIT
cleanup
for ns in inet r1 r2 h1 h2; do ip netns add $ns; ip -n $ns link set lo up; done

ip -n inet link add br0 type bridge
ip -n inet addr add 203.0.113.1/24 dev br0
ip -n inet link set br0 up

for i in 1 2; do
  # router WAN <-> internet bridge
  ip link add wan netns r$i type veth peer name p$i netns inet
  ip -n inet link set p$i master br0 up
  ip -n r$i addr add 203.0.113.1$i/24 dev wan
  ip -n r$i link set wan up
  # host <-> router LAN
  ip link add eth0 netns h$i type veth peer name lan netns r$i
  ip -n r$i addr add 10.$i.0.1/24 dev lan
  ip -n r$i link set lan up
  ip -n h$i addr add 10.$i.0.2/24 dev eth0
  ip -n h$i link set eth0 up
  ip -n h$i route add default via 10.$i.0.1
  # the NAT. A home router also firewalls unsolicited inbound traffic. Without this DROP, Linux
  # records the peer's first (unsolicited) ping in conntrack, that clashes with our outbound
  # mapping, and MASQUERADE picks a new port, which breaks the hole punch.
  ip netns exec r$i iptables -A INPUT -i wan -m conntrack --ctstate NEW -j DROP
  ip netns exec r$i sysctl -qw net.ipv4.ip_forward=1
  if [ "$MODE" = hard ]; then
    ip netns exec r$i iptables -t nat -A POSTROUTING -o wan -j MASQUERADE --random-fully
  else
    ip netns exec r$i iptables -t nat -A POSTROUTING -o wan -j MASQUERADE
  fi
done

ip netns exec inet "$BIN" derp -listen 203.0.113.1:3478 &
ip netns exec inet "$BIN" coord -listen 203.0.113.1:8080 -derp 203.0.113.1:3478 &
sleep 0.5
ip netns exec h1 "$BIN" node -name h1 -coord http://203.0.113.1:8080 -to h2 > /tmp/h1.log &
ip netns exec h2 "$BIN" node -name h2 -coord http://203.0.113.1:8080 -to h1 > /tmp/h2.log &
sleep 8

echo "── h1's view ($MODE NAT) ──"; tail -4 /tmp/h1.log
last=$(grep -- "-> h2 via" /tmp/h1.log | tail -1)
if [ "$MODE" = easy ]; then
  [[ $last == *direct* ]] && echo "PASS: hole-punched through both NATs" || { echo "FAIL: expected direct"; exit 1; }
else
  [[ $last == *derp* ]] && grep -q "<- h2 via derp" /tmp/h1.log && echo "PASS: symmetric NAT, fell back to DERP" || { echo "FAIL: expected derp"; exit 1; }
fi
