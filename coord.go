package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// A node that hasn't checked in for this long is treated as offline and left out of netmaps.
const offlineAfter = 10 * time.Second

// NodeInfo is what coord knows about one node. A node also sends one of these to check in.
type NodeInfo struct {
	Name      string
	Key       Key      // the node's public key
	IP        string   // the node's address inside the private network, e.g. 100.64.0.1
	Endpoints []string // every "ip:port" the node might be reachable at: LAN addresses + its public address
}

// MapResponse is the netmap: everything a node needs to know about its network.
type MapResponse struct {
	Self  NodeInfo   // the node that asked
	Peers []NodeInfo // the other nodes it is allowed to talk to
	DERP  string     // "ip:port" of the DERP server to use
}

// Coord is the coordination server: the address book every node checks in with.
type Coord struct {
	DERP string          // "ip:port" of the DERP server, handed to every node
	ACL  map[string]bool // allowed pairs of node names, like "alice-bob"; nil = everyone can talk

	lock        sync.Mutex // protects the two maps below, which many requests use at once
	nodesByKey  map[Key]*NodeInfo
	lastCheckIn map[Key]time.Time
}

// ServeHTTP is the whole control protocol: a node POSTs who it is and where it can be
// reached, and gets back its netmap. (Real Tailscale long-polls /machine/map over Noise.)
func (coord *Coord) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	var nodeReport NodeInfo
	if err := json.NewDecoder(request.Body).Decode(&nodeReport); err != nil {
		http.Error(response, "bad request", http.StatusBadRequest)
		return
	}
	netmap := coord.checkIn(nodeReport)
	json.NewEncoder(response).Encode(netmap)
}

// checkIn records what the node reported and builds the netmap to send back to it.
func (coord *Coord) checkIn(nodeReport NodeInfo) MapResponse {
	coord.lock.Lock()
	defer coord.lock.Unlock()
	caller := coord.register(nodeReport)
	return MapResponse{Self: *caller, Peers: coord.peersVisibleTo(caller), DERP: coord.DERP}
}

// register records the node's latest endpoints. On first contact it also allocates a tailnet IP.
func (coord *Coord) register(nodeReport NodeInfo) *NodeInfo {
	if coord.nodesByKey == nil {
		coord.nodesByKey = map[Key]*NodeInfo{}
		coord.lastCheckIn = map[Key]time.Time{}
	}
	knownNode := coord.nodesByKey[nodeReport.Key]
	if knownNode == nil {
		knownNode = &NodeInfo{Name: nodeReport.Name, Key: nodeReport.Key, IP: coord.nextFreeIP()}
		coord.nodesByKey[nodeReport.Key] = knownNode
	}
	knownNode.Endpoints = nodeReport.Endpoints
	coord.lastCheckIn[nodeReport.Key] = time.Now()
	return knownNode
}

func (coord *Coord) nextFreeIP() string {
	nodeNumber := len(coord.nodesByKey) + 1
	return fmt.Sprintf("100.64.0.%d", nodeNumber)
}

// peersVisibleTo is where the ACL is applied: a peer you aren't allowed to reach is left out
// of your netmap, so your node doesn't know its key and drops its packets.
func (coord *Coord) peersVisibleTo(caller *NodeInfo) []NodeInfo {
	var visiblePeers []NodeInfo
	for otherKey, otherNode := range coord.nodesByKey {
		isCallerItself := otherKey == caller.Key
		if isCallerItself || !coord.isOnline(otherKey) || !coord.allowed(caller.Name, otherNode.Name) {
			continue
		}
		visiblePeers = append(visiblePeers, *otherNode)
	}
	return visiblePeers
}

func (coord *Coord) isOnline(nodeKey Key) bool {
	timeSinceCheckIn := time.Since(coord.lastCheckIn[nodeKey])
	return timeSinceCheckIn <= offlineAfter
}

// allowed reports whether two nodes may talk. The pair can be written either way round.
func (coord *Coord) allowed(nodeName, otherNodeName string) bool {
	if coord.ACL == nil {
		return true
	}
	return coord.ACL[nodeName+"-"+otherNodeName] || coord.ACL[otherNodeName+"-"+nodeName]
}
