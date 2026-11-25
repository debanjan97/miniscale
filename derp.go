package main

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
)

// The toy STUN protocol: a node sends "STUN" over UDP, the server replies "STUN <ip:port>"
// with the address that request came from.
const (
	stunRequest     = "STUN"
	stunReplyPrefix = "STUN "
)

// DERP is the relay server. All it remembers is which nodes are connected to it right now.
type DERP struct {
	lock        sync.Mutex       // protects connections, which many goroutines use at once
	connections map[Key]net.Conn // node's public key -> the TCP connection that node opened to us
}

// Serve runs the relay on TCP and STUN on UDP. Real DERP runs over HTTPS (port 443), so it
// works even on networks that block all UDP. That's why it's the fallback of last resort.
func (relay *DERP) Serve(relayListener net.Listener, stunSocket *net.UDPConn) {
	relay.connections = map[Key]net.Conn{}
	go answerSTUN(stunSocket)
	for {
		connection, err := relayListener.Accept() // waits here until a node connects
		if err != nil {
			return
		}
		go relay.serveNode(connection)
	}
}

// answerSTUN tells each caller the source address its packet arrived from. For a node
// behind NAT, that is its public ip:port.
func answerSTUN(stunSocket *net.UDPConn) {
	requestBuffer := make([]byte, 64) // the request's contents don't matter, only where it came from
	for {
		_, callerAddress, err := stunSocket.ReadFromUDP(requestBuffer)
		if err != nil {
			return
		}
		reply := stunReplyPrefix + callerAddress.String()
		stunSocket.WriteToUDP([]byte(reply), callerAddress)
	}
}

// serveNode handles one node's connection: learn who it is, then forward whatever it sends.
func (relay *DERP) serveNode(connection net.Conn) {
	defer connection.Close()

	senderKey, err := readHello(connection)
	if err != nil {
		return
	}
	relay.remember(senderKey, connection)
	defer relay.forget(senderKey, connection)

	for {
		recipientKey, encryptedPacket, err := readFrame(connection)
		if err != nil {
			return // the node disconnected
		}
		relay.forward(senderKey, recipientKey, encryptedPacket)
	}
}

// readHello reads the first thing every node sends after connecting: its own public key.
func readHello(connection net.Conn) (Key, error) {
	var nodeKey Key
	_, err := io.ReadFull(connection, nodeKey[:])
	return nodeKey, err
}

func (relay *DERP) remember(nodeKey Key, connection net.Conn) {
	relay.lock.Lock()
	defer relay.lock.Unlock()
	relay.connections[nodeKey] = connection
}

func (relay *DERP) forget(nodeKey Key, connection net.Conn) {
	relay.lock.Lock()
	defer relay.lock.Unlock()
	nodeHasReconnected := relay.connections[nodeKey] != connection
	if !nodeHasReconnected {
		delete(relay.connections, nodeKey)
	}
}

// forward passes the encrypted packet on untouched. The frame the sender gave us named the
// recipient; the frame we give the recipient names the sender.
func (relay *DERP) forward(senderKey, recipientKey Key, encryptedPacket []byte) {
	relay.lock.Lock()
	defer relay.lock.Unlock()
	recipientConnection := relay.connections[recipientKey]
	if recipientConnection == nil {
		return // the recipient isn't connected: drop the packet
	}
	writeFrame(recipientConnection, senderKey, encryptedPacket)
}

// A frame is how one packet travels over a DERP connection:
//
//	[32-byte key][2-byte packet length][packet]
//
// The key names the other node. A node sending to DERP puts the recipient's key there;
// DERP sending to a node puts the sender's key there. That's why it is called otherNodeKey.
const (
	frameLengthSize = 2
	frameHeaderSize = keySize + frameLengthSize
)

func writeFrame(connection io.Writer, otherNodeKey Key, packet []byte) error {
	frame := make([]byte, frameHeaderSize+len(packet))
	keyPart := frame[:keySize]
	lengthPart := frame[keySize:frameHeaderSize]
	packetPart := frame[frameHeaderSize:]

	copy(keyPart, otherNodeKey[:])
	binary.BigEndian.PutUint16(lengthPart, uint16(len(packet)))
	copy(packetPart, packet)

	_, err := connection.Write(frame)
	return err
}

func readFrame(connection io.Reader) (otherNodeKey Key, packet []byte, err error) {
	var frameHeader [frameHeaderSize]byte
	if _, err := io.ReadFull(connection, frameHeader[:]); err != nil {
		return Key{}, nil, err
	}
	keyPart := frameHeader[:keySize]
	lengthPart := frameHeader[keySize:]

	copy(otherNodeKey[:], keyPart)
	packetLength := binary.BigEndian.Uint16(lengthPart)

	packet = make([]byte, packetLength)
	_, err = io.ReadFull(connection, packet)
	return otherNodeKey, packet, err
}
