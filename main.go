// miniscale: the smallest program that behaves like Tailscale's core, built to read, not to use.
//
// The three roles and their real Tailscale counterparts:
//
//	coord -> the control plane (login.tailscale.com, or Headscale). It hands every node a
//	         100.64.x.y IP, the public keys of its peers and their candidate ip:ports (the
//	         "netmap"). It never sees traffic, so you can kill it and existing tunnels keep working.
//	derp  -> a DERP server. It relays encrypted packets addressed by *public key* over TCP,
//	         and answers STUN ("what ip:port do you see me as?"). It can't decrypt anything.
//	node  -> tailscaled. Real tailscaled has WireGuard for encryption, magicsock (one UDP
//	         socket that picks the best path per peer) and disco (ping/pong/call-me-maybe
//	         for NAT traversal). All three are in Node below, much simplified.
//
// What's left out: the WireGuard Noise handshake (forward secrecy, replay protection), the
// TUN device and IP routing, login and machine keys, IPv6, and the details of real STUN.
//
// How to read the code, in this order:
//
//  1. main.go   how each of the three roles is started
//  2. coord.go  the address book (Coord)
//  3. derp.go   the relay, and "what is my public address?"
//  4. node.go   startup, talking to coord, encryption, receiving, disco, sending
package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const keySize = 32

// Key is a node's public key. It is also the node's identity: coord, DERP and peers all
// refer to a node by its Key.
type Key [keySize]byte

func (k Key) String() string { return fmt.Sprintf("%x", k[:4]) }

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	args := os.Args[2:]
	switch os.Args[1] {
	case "derp":
		runDERP(args)
	case "coord":
		runCoord(args)
	case "node":
		runNode(args)
	default:
		usage()
	}
}

func usage() {
	fmt.Println("usage: miniscale derp|coord|node [flags]")
	os.Exit(2)
}

func runDERP(args []string) {
	flags := flag.NewFlagSet("derp", flag.ExitOnError)
	listen := flags.String("listen", ":3478", "TCP relay + UDP STUN address")
	flags.Parse(args)

	tcp, err := net.Listen("tcp4", *listen)
	exitOn(err)
	udpAddr, err := net.ResolveUDPAddr("udp4", *listen)
	exitOn(err)
	udp, err := net.ListenUDP("udp4", udpAddr)
	exitOn(err)

	new(DERP).Serve(tcp, udp)
}

func runCoord(args []string) {
	flags := flag.NewFlagSet("coord", flag.ExitOnError)
	listen := flags.String("listen", ":8080", "HTTP address")
	derp := flags.String("derp", "127.0.0.1:3478", "DERP address handed to nodes")
	acl := flags.String("acl", "", "allowed pairs, e.g. a-b,b-c (empty = all)")
	flags.Parse(args)

	coord := &Coord{DERP: *derp, ACL: parseACL(*acl)}
	exitOn(http.ListenAndServe(*listen, coord))
}

// parseACL turns "a-b,b-c" into a set of allowed pairs. Empty input means no restrictions.
func parseACL(pairs string) map[string]bool {
	if pairs == "" {
		return nil
	}
	acl := map[string]bool{}
	for _, pair := range strings.Split(pairs, ",") {
		acl[pair] = true
	}
	return acl
}

func runNode(args []string) {
	flags := flag.NewFlagSet("node", flag.ExitOnError)
	name := flags.String("name", "", "node name")
	coord := flags.String("coord", "http://127.0.0.1:8080", "coord URL")
	to := flags.String("to", "", "peer to message every second")
	noDirect := flags.Bool("no-direct", false, "drop all UDP (forces DERP)")
	flags.Parse(args)

	node, err := NewNode(*name, *coord)
	exitOn(err)
	node.NoDirect.Store(*noDirect)

	go printReceived(node)
	for i := 0; ; i++ {
		time.Sleep(time.Second)
		if *to != "" {
			sendHello(node, *to, i)
		}
	}
}

func printReceived(node *Node) {
	for msg := range node.Recv {
		fmt.Printf("<- %s via %s: %s\n", msg.From, msg.Path, msg.Text)
	}
}

func sendHello(node *Node, to string, count int) {
	text := fmt.Sprintf("hello #%d from %s", count, node.Name)
	if err := node.Send(to, text); err == nil {
		fmt.Printf("-> %s via %s\n", to, node.Path(to))
	}
}

func exitOn(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
