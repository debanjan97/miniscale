# miniscale: Tailscale's core, in about a thousand lines of Go, for reading

| miniscale             | Real Tailscale                                    | What it teaches                                                      |
|----------------------|---------------------------------------------------|----------------------------------------------------------------------|
| `Coord.ServeHTTP`    | control plane `/machine/map` (or Headscale)       | Control only distributes keys, IPs and endpoints. It never sees traffic. |
| `Coord.allowed`      | ACLs / grants compiled into the netmap            | A peer you aren't allowed to reach isn't in your netmap, so its packets are dropped. |
| `DERP`               | DERP servers                                      | A relay that forwards ciphertext addressed by public key. It can't read anything. |
| DERP's UDP side      | STUN                                              | How a node learns its public `ip:port` behind NAT.                   |
| `Node.udpSocket`     | magicsock                                         | One UDP socket carries every peer and every disco message.           |
| `disco()` + `handle` | disco: ping, pong, CallMeMaybe                    | Path discovery and hole punching, with both sides sending at once.   |
| `Send` / `Path`      | magicsock's path choice, `trustUDPAddrDuration`   | Go direct while it's proven to work, otherwise DERP. Switches either way at any time. |
| `sessionKey`/`seal`  | WireGuard                                         | Packets are end-to-end encrypted to a peer's public key.             |

Left out: the Noise IK handshake (forward secrecy, replay protection), the TUN device and IP routing, login and node keys, IPv6, and the details of real STUN.

## Testing

```bash
go test -v -race ./...        # layers 1+2: crypto, frames, direct upgrade, relay fallback,
                              # fallback when direct dies, ACL, control plane down
sudo ./nat_test.sh easy       # layer 3: two NATed hosts in network namespaces -> direct
sudo ./nat_test.sh hard       # layer 3: symmetric NAT (--random-fully)         -> stays on DERP
```

### Layer 4: two real machines (by hand)

Build the binary on each machine with `go build`. Then, on a cloud VM with UDP 3478 and TCP 3478 and 8080 open:

```bash
./miniscale derp  -listen :3478
./miniscale coord -listen :8080 -derp <VM_PUBLIC_IP>:3478
```

On your laptop (home Wi-Fi) and on a second machine on a phone hotspot:

```bash
./miniscale node -name laptop -coord http://<VM_PUBLIC_IP>:8080 -to phone
./miniscale node -name phone  -coord http://<VM_PUBLIC_IP>:8080 -to laptop
```

Watch the `via` column. It starts on `derp` and switches to `direct <ip:port>` if hole punching works. Mobile carriers often use symmetric NAT (carrier-grade NAT), in which case it stays on DERP. That's the same thing `tailscale status` / `tailscale ping` would show you.
