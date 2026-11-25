package main

import (
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ── Layer 1: unit tests ──

func TestTamperedPacketRejected(t *testing.T) {
	coord, _ := tailnet(t, nil)
	a, b := node(t, "a", coord), node(t, "b", coord)
	waitFor(t, "peers known", 5*time.Second, func() bool { return a.peer("b") != nil && b.peer("a") != nil })

	pkt := a.seal(a.peer("b"), pData, []byte("secret"))
	pkt[len(pkt)-1] ^= 1 // flip one bit of the ciphertext
	b.handle(pkt, nil)
	b.handle(a.seal(a.peer("b"), pData, []byte("ok")), nil)
	if m := <-b.Recv; m.Text != "ok" {
		t.Fatalf("tampered packet was accepted: %q", m.Text)
	}
}

func TestFrameRoundTrip(t *testing.T) {
	var buf strings.Builder
	writeFrame(&buf, Key{1, 2, 3}, []byte("payload"))
	k, p, err := readFrame(strings.NewReader(buf.String()))
	if err != nil || k != (Key{1, 2, 3}) || string(p) != "payload" {
		t.Fatal(k, string(p), err)
	}
}

// ── Layer 2: end to end on one machine ──

func TestUpgradesToDirect(t *testing.T) {
	coord, _ := tailnet(t, nil)
	a, b := node(t, "a", coord), node(t, "b", coord)
	waitFor(t, "a->b direct", 5*time.Second, func() bool { return strings.HasPrefix(a.Path("b"), "direct") })
	expectMsg(t, a, b, "direct")
}

func TestRelayFallback(t *testing.T) {
	coord, _ := tailnet(t, nil)
	a, b := node(t, "a", coord), node(t, "b", coord)
	b.NoDirect.Store(true) // b is behind a firewall that drops UDP
	waitFor(t, "peers known", 5*time.Second, func() bool { return a.peer("b") != nil && b.peer("a") != nil })
	time.Sleep(3 * time.Second) // give disco time to fail
	if a.Path("b") != "derp" {
		t.Fatalf("expected derp, got %s", a.Path("b"))
	}
	expectMsg(t, a, b, "derp")
}

func TestFallsBackWhenDirectDies(t *testing.T) {
	coord, _ := tailnet(t, nil)
	a, b := node(t, "a", coord), node(t, "b", coord)
	waitFor(t, "direct", 5*time.Second, func() bool { return strings.HasPrefix(a.Path("b"), "direct") })
	b.NoDirect.Store(true) // UDP stops working partway through
	waitFor(t, "back to derp", 10*time.Second, func() bool { return a.Path("b") == "derp" })
	expectMsg(t, a, b, "derp")
}

func TestACL(t *testing.T) {
	coord, _ := tailnet(t, map[string]bool{"a-b": true})
	a, b, c := node(t, "a", coord), node(t, "b", coord), node(t, "c", coord)
	waitFor(t, "a sees b", 5*time.Second, func() bool { return a.peer("b") != nil })
	time.Sleep(time.Second)
	if a.peer("c") != nil || c.peer("a") != nil {
		t.Fatal("c should not be in a's netmap")
	}
	if err := c.Send("a", "hi"); err == nil {
		t.Fatal("c could address a")
	}
	_ = b
}

func TestControlPlaneNotInDataPath(t *testing.T) {
	coord, srv := tailnet(t, nil)
	a, b := node(t, "a", coord), node(t, "b", coord)
	waitFor(t, "direct", 5*time.Second, func() bool { return strings.HasPrefix(a.Path("b"), "direct") })
	srv.Close() // kill the coordination server
	time.Sleep(2 * time.Second)
	expectMsg(t, a, b, "direct")
}

// ── helpers ──

// tailnet starts DERP and coord in-process and returns coord's URL.
func tailnet(t *testing.T, acl map[string]bool) (string, *httptest.Server) {
	tcp, _ := net.Listen("tcp4", "127.0.0.1:0")
	port := tcp.Addr().(*net.TCPAddr).Port
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	go new(DERP).Serve(tcp, udp)
	srv := httptest.NewServer(&Coord{DERP: tcp.Addr().String(), ACL: acl})
	t.Cleanup(func() { tcp.Close(); udp.Close(); srv.Close() })
	return srv.URL, srv
}

func node(t *testing.T, name, coord string) *Node {
	n, err := NewNode(name, coord)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(n.Close)
	return n
}

func expectMsg(t *testing.T, from, to *Node, wantPath string) {
	t.Helper()
	if err := from.Send(to.Name, "hello"); err != nil {
		t.Fatal(err)
	}
	select {
	case m := <-to.Recv:
		if m.Text != "hello" || !strings.HasPrefix(m.Path, wantPath) {
			t.Fatalf("got %+v, want path %s", m, wantPath)
		}
		t.Logf("%s -> %s via %s", from.Name, to.Name, m.Path)
	case <-time.After(3 * time.Second):
		t.Fatal("message never arrived")
	}
}

func waitFor(t *testing.T, what string, d time.Duration, f func() bool) {
	t.Helper()
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(100 * time.Millisecond) {
		if f() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}
