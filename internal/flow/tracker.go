package flow

import (
	"fmt"
	"sync"
	"time"
)

// TCPState represents the state of a TCP connection.
type TCPState string

const (
	TCPStateNew         TCPState = "NEW"
	TCPStateSynSent     TCPState = "SYN_SENT"
	TCPStateSynReceived TCPState = "SYN_RECEIVED"
	TCPStateEstablished TCPState = "ESTABLISHED"
	TCPStateFinWait     TCPState = "FIN_WAIT"
	TCPStateClosed      TCPState = "CLOSED"
)

// FlowKey is a normalized 5-tuple. Both directions map to the same flow.
type FlowKey struct {
	IP1      string
	IP2      string
	Port1    uint16
	Port2    uint16
	Protocol string
}

func MakeFlowKey(srcIP, dstIP string, srcPort, dstPort uint16, protocol string) FlowKey {
	// Normalize: smaller IP first; if IPs equal, smaller port first
	if srcIP < dstIP || (srcIP == dstIP && srcPort < dstPort) {
		return FlowKey{IP1: srcIP, IP2: dstIP, Port1: srcPort, Port2: dstPort, Protocol: protocol}
	}
	return FlowKey{IP1: dstIP, IP2: srcIP, Port1: dstPort, Port2: dstPort, Protocol: protocol}
}

// Flow holds statistics for a single network flow.
type Flow struct {
	ID          uint64   `json:"id"`
	SrcIP       string   `json:"srcIp"`
	DstIP       string   `json:"dstIp"`
	SrcPort     uint16   `json:"srcPort"`
	DstPort     uint16   `json:"dstPort"`
	Protocol    string   `json:"protocol"`
	PacketCount int      `json:"packetCount"`
	ByteCount   int64    `json:"byteCount"`
	FirstSeen   int64    `json:"firstSeen"` // unix ms
	LastSeen    int64    `json:"lastSeen"`  // unix ms
	TCPState    TCPState `json:"tcpState,omitempty"`
	FwdPackets  int      `json:"fwdPackets"`
	FwdBytes    int64    `json:"fwdBytes"`
	RevPackets  int      `json:"revPackets"`
	RevBytes    int64    `json:"revBytes"`
}

// TCPFlags holds parsed TCP flag bits.
type TCPFlags struct {
	SYN bool
	ACK bool
	FIN bool
	RST bool
	PSH bool
}

// Tracker maintains the flow table.
type Tracker struct {
	mu       sync.Mutex
	flows    map[FlowKey]*Flow
	nextID   uint64
	maxFlows int
	idleTime time.Duration
}

// NewTracker creates a new flow tracker.
func NewTracker() *Tracker {
	return &Tracker{
		flows:    make(map[FlowKey]*Flow),
		maxFlows: 10000,
		idleTime: 5 * time.Minute,
	}
}

// Track records a packet in the flow table and returns the flow ID and flow reference.
func (t *Tracker) Track(srcIP, dstIP string, srcPort, dstPort uint16, protocol string, length int, flags TCPFlags) (uint64, *Flow) {
	key := MakeFlowKey(srcIP, dstIP, srcPort, dstPort, protocol)
	now := time.Now().UnixMilli()

	t.mu.Lock()
	defer t.mu.Unlock()

	// Evict idle flows if at capacity
	if len(t.flows) >= t.maxFlows {
		t.evictIdle(now)
	}

	f, exists := t.flows[key]
	if !exists {
		t.nextID++
		f = &Flow{
			ID:        t.nextID,
			SrcIP:     srcIP,
			DstIP:     dstIP,
			SrcPort:   srcPort,
			DstPort:   dstPort,
			Protocol:  protocol,
			FirstSeen: now,
			TCPState:  TCPStateNew,
		}
		t.flows[key] = f
	}

	f.PacketCount++
	f.ByteCount += int64(length)
	f.LastSeen = now

	// Directional stats — "forward" = matches original src
	if srcIP == f.SrcIP && srcPort == f.SrcPort {
		f.FwdPackets++
		f.FwdBytes += int64(length)
	} else {
		f.RevPackets++
		f.RevBytes += int64(length)
	}

	// TCP state machine
	if protocol == "TCP" || protocol == "tcp" {
		f.TCPState = advanceTCPState(f.TCPState, flags)
	}

	return f.ID, f
}

// GetFlows returns a snapshot of all active flows.
func (t *Tracker) GetFlows() []*Flow {
	t.mu.Lock()
	defer t.mu.Unlock()

	result := make([]*Flow, 0, len(t.flows))
	for _, f := range t.flows {
		cp := *f
		result = append(result, &cp)
	}
	return result
}

// Reset clears all flows.
func (t *Tracker) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.flows = make(map[FlowKey]*Flow)
	t.nextID = 0
}

func (t *Tracker) evictIdle(nowMs int64) {
	cutoff := nowMs - t.idleTime.Milliseconds()
	for key, f := range t.flows {
		if f.LastSeen < cutoff {
			delete(t.flows, key)
		}
	}
}

func advanceTCPState(current TCPState, flags TCPFlags) TCPState {
	if flags.RST {
		return TCPStateClosed
	}

	switch current {
	case TCPStateNew:
		if flags.SYN && !flags.ACK {
			return TCPStateSynSent
		}
	case TCPStateSynSent:
		if flags.SYN && flags.ACK {
			return TCPStateSynReceived
		}
	case TCPStateSynReceived:
		if flags.ACK && !flags.SYN {
			return TCPStateEstablished
		}
	case TCPStateEstablished:
		if flags.FIN {
			return TCPStateFinWait
		}
	case TCPStateFinWait:
		if flags.FIN || flags.ACK {
			return TCPStateClosed
		}
	}
	return current
}

// String returns a human-readable description of the flow.
func (f *Flow) String() string {
	return fmt.Sprintf("Flow#%d %s:%d <-> %s:%d [%s] pkts=%d bytes=%d",
		f.ID, f.SrcIP, f.SrcPort, f.DstIP, f.DstPort, f.Protocol, f.PacketCount, f.ByteCount)
}
