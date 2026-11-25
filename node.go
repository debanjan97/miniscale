package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	controlPollInterval = 500 * time.Millisecond
	discoInterval       = time.Second

	// A direct path is trusted for this long after the last pong on it. Same idea as
	// magicsock's trustUDPAddrDuration.
	directPathTrustDuration = 6500 * time.Millisecond
)

// Msg is an application message handed to whoever is using the Node.
type Msg struct {
	From string // name of the peer that sent it
	Text string
	Path string // how it got here: "direct ip:port" or "derp"
}

type Node struct {
	Name     string
	Key      Key         // my public key
	NoDirect atomic.Bool // when set, acts like a network that drops all UDP (forces DERP)
	Recv     chan Msg    // messages from peers arrive here

	privateKey *ecdh.PrivateKey
	coordURL   string
	udpSocket  *net.UDPConn  // magicsock: one socket for all peers and all disco traffic
	closed     chan struct{} // closing this channel tells the background loops to stop

	derpLock       sync.Mutex // protects derpConnection
	derpConnection net.Conn   // nil while not connected

	lock           sync.Mutex // protects the fields below, and the changing fields of every Peer
	peersByKey     map[Key]*Peer
	publicEndpoint string // my "ip:port" as seen from outside the NAT; "" until STUN answers
}

// Peer is another node that the netmap says I may talk to.
type Peer struct {
	key           Key         // the peer's public key
	sessionCipher cipher.AEAD // encrypts and decrypts with the secret I share with this peer (stands in for a WireGuard session)

	// The fields below change over time and are protected by Node.lock.
	info          NodeInfo     // the latest from coord
	directAddress *net.UDPAddr // the direct path, if disco has found one
	lastPongTime  time.Time    // when that direct path was last proven to work
}

func NewNode(name, coordURL string) (*Node, error) {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	anyFreePort := &net.UDPAddr{}
	udpSocket, err := net.ListenUDP("udp4", anyFreePort)
	if err != nil {
		return nil, err
	}
	node := &Node{
		Name:       name,
		Recv:       make(chan Msg, 100),
		privateKey: privateKey,
		coordURL:   coordURL,
		udpSocket:  udpSocket,
		closed:     make(chan struct{}),
		peersByKey: map[Key]*Peer{},
	}
	copy(node.Key[:], privateKey.PublicKey().Bytes())

	// A node is these three loops. Everything below is called from one of them, or from Send.
	go node.readUDP()
	go node.repeat(controlPollInterval, node.pollControl)
	go node.repeat(discoInterval, node.disco)
	return node, nil
}

func (node *Node) Close() {
	close(node.closed)
	node.udpSocket.Close()
	node.derpLock.Lock()
	defer node.derpLock.Unlock()
	if node.derpConnection != nil {
		node.derpConnection.Close()
	}
}

// repeat runs task now, and then again every interval until the node is closed.
func (node *Node) repeat(interval time.Duration, task func()) {
	for {
		task()
		select {
		case <-node.closed:
			return
		case <-time.After(interval):
		}
	}
}

// ── node: talking to the control plane ──

// pollControl: report my endpoints, get my netmap, and act on it.
func (node *Node) pollControl() {
	netmap, err := node.fetchNetmap()
	if err != nil {
		return // control plane down: no new info, but existing peers keep working
	}
	node.updatePeers(netmap.Peers)
	if netmap.DERP != "" {
		node.connectDERP(netmap.DERP)
		node.sendSTUNRequest(netmap.DERP)
	}
}

func (node *Node) fetchNetmap() (MapResponse, error) {
	var netmap MapResponse
	myReport := NodeInfo{Name: node.Name, Key: node.Key, Endpoints: node.endpoints()}
	requestBody, err := json.Marshal(myReport)
	if err != nil {
		return netmap, err
	}
	response, err := http.Post(node.coordURL, "application/json", bytes.NewReader(requestBody))
	if err != nil {
		return netmap, err
	}
	defer response.Body.Close()
	err = json.NewDecoder(response.Body).Decode(&netmap)
	return netmap, err
}

// updatePeers makes my peer list match the netmap: add the new, refresh the known, drop the gone.
func (node *Node) updatePeers(peersInNetmap []NodeInfo) {
	node.lock.Lock()
	defer node.lock.Unlock()
	isInNetmap := map[Key]bool{}
	for _, peerInfo := range peersInNetmap {
		isInNetmap[peerInfo.Key] = true
		peer := node.peersByKey[peerInfo.Key]
		if peer == nil {
			sessionCipher, err := node.sessionKey(peerInfo.Key)
			if err != nil {
				continue // unusable public key: ignore this peer
			}
			peer = &Peer{key: peerInfo.Key, sessionCipher: sessionCipher}
			node.peersByKey[peerInfo.Key] = peer
		}
		peer.info = peerInfo
	}
	for peerKey := range node.peersByKey {
		if !isInNetmap[peerKey] {
			delete(node.peersByKey, peerKey)
		}
	}
}

// endpoints: every "ip:port" a peer might be able to reach this node's UDP socket at.
func (node *Node) endpoints() []string {
	endpoints := node.localEndpoints()
	if publicEndpoint := node.currentPublicEndpoint(); publicEndpoint != "" {
		endpoints = append(endpoints, publicEndpoint)
	}
	return endpoints
}

// localEndpoints pairs each of this machine's IPv4 addresses with the UDP socket's port.
// These work for peers on the same LAN.
func (node *Node) localEndpoints() []string {
	socketPort := node.udpSocket.LocalAddr().(*net.UDPAddr).Port
	var endpoints []string
	machineAddresses, _ := net.InterfaceAddrs()
	for _, machineAddress := range machineAddresses {
		ipNetwork, isIPAddress := machineAddress.(*net.IPNet)
		if isIPAddress && ipNetwork.IP.To4() != nil {
			endpoints = append(endpoints, fmt.Sprintf("%s:%d", ipNetwork.IP, socketPort))
		}
	}
	return endpoints
}

func (node *Node) currentPublicEndpoint() string {
	node.lock.Lock()
	defer node.lock.Unlock()
	return node.publicEndpoint
}

func (node *Node) setPublicEndpoint(endpoint string) {
	node.lock.Lock()
	defer node.lock.Unlock()
	node.publicEndpoint = endpoint
}

// sendSTUNRequest asks the server what my public address is. It only sends the question.
// The answer comes back later on the same socket: readUDP receives it and calls
// setPublicEndpoint to store it.
//
// The request must leave from udpSocket, the socket peers talk to, because the NAT
// mapping we want to learn belongs to that socket.
func (node *Node) sendSTUNRequest(stunServer string) {
	stunServerAddress, err := net.ResolveUDPAddr("udp4", stunServer)
	if err != nil {
		return
	}
	node.udpSocket.WriteToUDP([]byte(stunRequest), stunServerAddress)
}

// ── node: encryption ──

// A packet is what two nodes send each other, whether directly or through DERP:
//
//	[1-byte type][32-byte sender key][12-byte nonce][ciphertext]
//	└────────── header ────────────┘
//
// The header is not encrypted (the receiver needs the sender key to pick the right cipher)
// but it is authenticated, so changing it makes decryption fail.
//
// The nonce is a random number that makes every encryption come out different, even when
// the same text is sent twice.
type packetType byte

const (
	pData        packetType = 1 // an application packet (in real Tailscale, a WireGuard-wrapped IP packet)
	pPing        packetType = 2 // disco ping: "can you hear me on this ip:port?"
	pPong        packetType = 3 // disco pong: "yes", which proves the path works in both directions
	pCallMeMaybe packetType = 4 // sent via DERP: "here are my endpoints, ping me now" (so both sides punch at once)
)

const (
	typeSize      = 1
	nonceSize     = 12
	headerSize    = typeSize + keySize
	minPacketSize = headerSize + nonceSize
)

// parsedPacket is a packet's bytes split into the parts drawn above.
type parsedPacket struct {
	packetType packetType
	senderKey  Key
	header     []byte
	nonce      []byte
	ciphertext []byte
}

func parsePacket(packetBytes []byte) (packet parsedPacket, isValid bool) {
	if len(packetBytes) < minPacketSize {
		return parsedPacket{}, false
	}
	packet = parsedPacket{
		packetType: packetType(packetBytes[0]),
		header:     packetBytes[:headerSize],
		nonce:      packetBytes[headerSize:minPacketSize],
		ciphertext: packetBytes[minPacketSize:],
	}
	copy(packet.senderKey[:], packetBytes[typeSize:headerSize])
	return packet, true
}

// sessionKey: X25519(my private, their public), the same on both sides. Real WireGuard runs
// a Noise IK handshake on top of these static keys to get fresh, short-lived session keys.
func (node *Node) sessionKey(peerKey Key) (cipher.AEAD, error) {
	peerPublicKey, err := ecdh.X25519().NewPublicKey(peerKey[:])
	if err != nil {
		return nil, err
	}
	sharedSecret, err := node.privateKey.ECDH(peerPublicKey)
	if err != nil {
		return nil, err
	}
	encryptionKey := sha256.Sum256(sharedSecret)
	aesCipher, err := aes.NewCipher(encryptionKey[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(aesCipher)
}

// seal builds an encrypted packet that only `recipient` can open.
func (node *Node) seal(recipient *Peer, packetType packetType, plaintext []byte) []byte {
	header := append([]byte{byte(packetType)}, node.Key[:]...)
	nonce := make([]byte, nonceSize)
	rand.Read(nonce)
	headerAndNonce := append(header, nonce...)
	// Seal appends the ciphertext to headerAndNonce, which gives the whole packet.
	return recipient.sessionCipher.Seal(headerAndNonce, nonce, plaintext, header)
}

// open decrypts a packet. It fails if the packet was forged or changed on the way.
func (peer *Peer) open(packet parsedPacket) (plaintext []byte, err error) {
	return peer.sessionCipher.Open(nil, packet.nonce, packet.ciphertext, packet.header)
}

// ── node: the DERP connection ──

func (node *Node) connectDERP(derpAddress string) {
	node.derpLock.Lock()
	defer node.derpLock.Unlock()
	alreadyConnected := node.derpConnection != nil
	if alreadyConnected {
		return
	}
	connection, err := net.Dial("tcp", derpAddress)
	if err != nil {
		return
	}
	connection.Write(node.Key[:]) // the hello: "I am <pubkey>"
	node.derpConnection = connection
	go node.readDERP(connection)
}

func (node *Node) readDERP(connection net.Conn) {
	defer connection.Close()
	for {
		_, packetBytes, err := readFrame(connection)
		if err != nil {
			node.forgetDERP() // the next pollControl reconnects
			return
		}
		viaDERP := (*net.UDPAddr)(nil)
		node.handle(packetBytes, viaDERP)
	}
}

func (node *Node) forgetDERP() {
	node.derpLock.Lock()
	defer node.derpLock.Unlock()
	node.derpConnection = nil
}

func (node *Node) sendDERP(recipientKey Key, packetBytes []byte) {
	node.derpLock.Lock()
	defer node.derpLock.Unlock()
	if node.derpConnection != nil {
		writeFrame(node.derpConnection, recipientKey, packetBytes)
	}
}

// ── node: receiving ──

func (node *Node) readUDP() {
	buffer := make([]byte, 65535) // big enough for the largest possible UDP datagram
	for {
		size, senderAddress, err := node.udpSocket.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		datagram := append([]byte(nil), buffer[:size]...) // copy, because buffer is reused
		if myPublicEndpoint, isSTUNReply := strings.CutPrefix(string(datagram), stunReplyPrefix); isSTUNReply {
			node.setPublicEndpoint(myPublicEndpoint)
			continue
		}
		if node.NoDirect.Load() {
			continue // simulated firewall: all UDP dropped
		}
		node.handle(datagram, senderAddress)
	}
}

// handle runs for every packet. senderAddress is where it came from if it arrived directly
// over UDP, and nil if it arrived via DERP.
func (node *Node) handle(packetBytes []byte, senderAddress *net.UDPAddr) {
	packet, isValid := parsePacket(packetBytes)
	if !isValid {
		return
	}
	sender := node.peerByKey(packet.senderKey)
	if sender == nil {
		return // not in my netmap means not allowed (ACL), or unknown: drop
	}
	plaintext, err := sender.open(packet)
	if err != nil {
		return // forged or tampered
	}
	switch packet.packetType {
	case pData:
		node.deliver(sender, plaintext, senderAddress)
	case pPing:
		node.answerPing(sender, plaintext, senderAddress)
	case pPong:
		node.trustDirectPath(sender, senderAddress)
	case pCallMeMaybe:
		node.pingBack(sender, plaintext)
	}
}

// deliver hands a message to the application. If nobody is reading Recv, it is dropped.
func (node *Node) deliver(sender *Peer, text []byte, senderAddress *net.UDPAddr) {
	message := Msg{From: node.nameOf(sender), Text: string(text), Path: pathName(senderAddress)}
	select {
	case node.Recv <- message:
	default:
	}
}

// answerPing replies on the same path the ping arrived on, echoing the ping's ID.
func (node *Node) answerPing(sender *Peer, pingID []byte, senderAddress *net.UDPAddr) {
	pong := node.seal(sender, pPong, pingID)
	arrivedDirectly := senderAddress != nil
	if arrivedDirectly {
		node.udpSocket.WriteToUDP(pong, senderAddress)
	} else {
		node.sendDERP(sender.key, pong)
	}
}

// trustDirectPath: a pong that arrived over UDP proves that ip:port works in both directions.
// A pong that arrived via DERP proves nothing about a direct path, so it is ignored.
func (node *Node) trustDirectPath(sender *Peer, senderAddress *net.UDPAddr) {
	arrivedViaDERP := senderAddress == nil
	if arrivedViaDERP {
		return
	}
	node.lock.Lock()
	defer node.lock.Unlock()
	sender.directAddress = senderAddress
	sender.lastPongTime = time.Now()
}

// pingBack answers a call-me-maybe. The peer is pinging me right now, so I ping its
// endpoints too: with both sides sending at once, both NATs open.
func (node *Node) pingBack(sender *Peer, senderEndpointsJSON []byte) {
	var senderEndpoints []string
	json.Unmarshal(senderEndpointsJSON, &senderEndpoints)
	node.pingEndpoints(sender, senderEndpoints)
}

// ── node: disco (finding and keeping a direct path) ──

// disco runs every second. A peer with a trusted direct path gets one ping to keep the NAT
// mapping open. A peer without one gets a hole-punching attempt.
func (node *Node) disco() {
	for _, peer := range node.allPeers() {
		if directAddress := node.trustedDirectPath(peer); directAddress != nil {
			node.sendPing(peer, directAddress)
		} else {
			node.punchHole(peer)
		}
	}
}

// punchHole pings every address the peer might be at, and asks it (through DERP, which
// always works) to ping me at the same moment.
func (node *Node) punchHole(peer *Peer) {
	node.pingEndpoints(peer, node.endpointsOf(peer))
	if node.NoDirect.Load() {
		return
	}
	myEndpointsJSON, _ := json.Marshal(node.endpoints())
	callMeMaybe := node.seal(peer, pCallMeMaybe, myEndpointsJSON)
	node.sendDERP(peer.key, callMeMaybe)
}

func (node *Node) pingEndpoints(peer *Peer, endpoints []string) {
	for _, endpoint := range endpoints {
		address, err := net.ResolveUDPAddr("udp4", endpoint)
		if err != nil {
			continue
		}
		node.sendPing(peer, address)
	}
}

func (node *Node) sendPing(peer *Peer, address *net.UDPAddr) {
	if node.NoDirect.Load() {
		return
	}
	var pingID [8]byte // random, so every ping is different; the pong echoes it back
	rand.Read(pingID[:])
	ping := node.seal(peer, pPing, pingID[:])
	node.udpSocket.WriteToUDP(ping, address)
}

// ── node: sending ──

// Send is magicsock's send path: use the direct path if it's trusted, otherwise DERP.
func (node *Node) Send(peerNameOrIP, text string) error {
	peer := node.peer(peerNameOrIP)
	if peer == nil {
		return fmt.Errorf("%s: not in netmap", peerNameOrIP)
	}
	packetBytes := node.seal(peer, pData, []byte(text))
	directAddress := node.trustedDirectPath(peer)
	if directAddress != nil && !node.NoDirect.Load() {
		_, err := node.udpSocket.WriteToUDP(packetBytes, directAddress)
		return err
	}
	node.sendDERP(peer.key, packetBytes)
	return nil
}

// Path reports how packets to this peer go right now: "direct ip:port" or "derp".
func (node *Node) Path(peerNameOrIP string) string {
	peer := node.peer(peerNameOrIP)
	if peer == nil {
		return "unknown"
	}
	return pathName(node.trustedDirectPath(peer))
}

// pathName describes a path for display. A nil address means the path goes through DERP.
func pathName(directAddress *net.UDPAddr) string {
	if directAddress == nil {
		return "derp"
	}
	return "direct " + directAddress.String()
}

// ── node: peer lookups (each takes the lock, so callers don't have to) ──

// peer is a tiny MagicDNS: look a peer up by name or tailnet IP.
func (node *Node) peer(nameOrIP string) *Peer {
	node.lock.Lock()
	defer node.lock.Unlock()
	for _, peer := range node.peersByKey {
		if peer.info.Name == nameOrIP || peer.info.IP == nameOrIP {
			return peer
		}
	}
	return nil
}

func (node *Node) peerByKey(peerKey Key) *Peer {
	node.lock.Lock()
	defer node.lock.Unlock()
	return node.peersByKey[peerKey]
}

func (node *Node) allPeers() []*Peer {
	node.lock.Lock()
	defer node.lock.Unlock()
	peers := make([]*Peer, 0, len(node.peersByKey))
	for _, peer := range node.peersByKey {
		peers = append(peers, peer)
	}
	return peers
}

func (node *Node) nameOf(peer *Peer) string {
	node.lock.Lock()
	defer node.lock.Unlock()
	return peer.info.Name
}

func (node *Node) endpointsOf(peer *Peer) []string {
	node.lock.Lock()
	defer node.lock.Unlock()
	return peer.info.Endpoints
}

// trustedDirectPath returns the peer's direct address if a pong arrived on it recently,
// or nil if packets should go through DERP.
func (node *Node) trustedDirectPath(peer *Peer) *net.UDPAddr {
	node.lock.Lock()
	defer node.lock.Unlock()
	timeSinceLastPong := time.Since(peer.lastPongTime)
	if peer.directAddress == nil || timeSinceLastPong >= directPathTrustDuration {
		return nil
	}
	return peer.directAddress
}
