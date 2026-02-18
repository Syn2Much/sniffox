package stream

import (
	"encoding/base64"
	"encoding/json"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

const (
	maxStreamBuffer = 256 * 1024 // 256KB per direction
	inputChanCap    = 4096
	flushInterval   = 30 * time.Second
)

// Broadcaster is implemented by the engine to send stream events to clients.
type Broadcaster interface {
	BroadcastStreamEvent(eventType string, payload json.RawMessage)
}

// StreamData holds the reassembled data for one stream.
type StreamData struct {
	ID         uint64           `json:"id"`
	ClientData []byte           `json:"-"`
	ServerData []byte           `json:"-"`
	HTTPInfo   *HTTPTransaction `json:"httpInfo,omitempty"`
	SrcAddr    string           `json:"srcAddr"`
	DstAddr    string           `json:"dstAddr"`
	SrcPort    uint16           `json:"srcPort"`
	DstPort    uint16           `json:"dstPort"`
	StartTime  time.Time        `json:"startTime"`
	LastSeen   time.Time        `json:"lastSeen"`
}

// StreamDataResponse is what we send to clients.
type StreamDataResponse struct {
	StreamID   uint64           `json:"streamId"`
	ClientData string           `json:"clientData"` // base64
	ServerData string           `json:"serverData"` // base64
	HTTPInfo   *HTTPTransaction `json:"httpInfo,omitempty"`
}

// Manager coordinates TCP stream reassembly.
type Manager struct {
	mu          sync.Mutex
	factory     *sniffoxStreamFactory
	assembler   *tcpassembly.Assembler
	pool        *tcpassembly.StreamPool
	streams     map[uint64]*StreamData
	lookupMap   map[flowKey]uint64 // (net,transport) -> streamID
	inputCh     chan gopacket.Packet
	stopCh      chan struct{}
	broadcaster Broadcaster
	nextID      uint64
}

type flowKey struct {
	net       string
	transport string
}

// NewManager creates a new stream reassembly manager.
func NewManager(broadcaster Broadcaster) *Manager {
	m := &Manager{
		streams:     make(map[uint64]*StreamData),
		lookupMap:   make(map[flowKey]uint64),
		inputCh:     make(chan gopacket.Packet, inputChanCap),
		stopCh:      make(chan struct{}),
		broadcaster: broadcaster,
	}

	m.factory = &sniffoxStreamFactory{mgr: m}
	m.pool = tcpassembly.NewStreamPool(m.factory)
	m.assembler = tcpassembly.NewAssembler(m.pool)

	return m
}

// Feed sends a packet to the assembler goroutine. Non-blocking.
func (m *Manager) Feed(pkt gopacket.Packet) {
	select {
	case m.inputCh <- pkt:
	default:
		// Drop if channel full — assembler can't keep up
	}
}

// Start launches the assembler goroutine and flush ticker.
func (m *Manager) Start() {
	go m.assembleLoop()
}

// Stop signals the assembler to stop.
func (m *Manager) Stop() {
	close(m.stopCh)
}

// GetStreamData returns the reassembled data for a stream.
func (m *Manager) GetStreamData(id uint64) *StreamDataResponse {
	m.mu.Lock()
	defer m.mu.Unlock()

	sd, ok := m.streams[id]
	if !ok {
		return nil
	}

	resp := &StreamDataResponse{
		StreamID:   id,
		ClientData: base64.StdEncoding.EncodeToString(sd.ClientData),
		ServerData: base64.StdEncoding.EncodeToString(sd.ServerData),
		HTTPInfo:   sd.HTTPInfo,
	}
	return resp
}

// GetStreamID returns the stream ID for a given network/transport flow.
func (m *Manager) GetStreamID(netFlow, tcpFlow gopacket.Flow) uint64 {
	key := makeFlowKey(netFlow, tcpFlow)
	reverseKey := makeFlowKey(netFlow.Reverse(), tcpFlow.Reverse())

	m.mu.Lock()
	defer m.mu.Unlock()

	if id, ok := m.lookupMap[key]; ok {
		return id
	}
	if id, ok := m.lookupMap[reverseKey]; ok {
		return id
	}
	return 0
}

func makeFlowKey(net, transport gopacket.Flow) flowKey {
	return flowKey{
		net:       net.String(),
		transport: transport.String(),
	}
}

func (m *Manager) assembleLoop() {
	flushTicker := time.NewTicker(flushInterval)
	defer flushTicker.Stop()

	for {
		select {
		case <-m.stopCh:
			m.assembler.FlushAll()
			return
		case pkt, ok := <-m.inputCh:
			if !ok {
				return
			}
			tcpLayer := pkt.Layer(layers.LayerTypeTCP)
			if tcpLayer == nil {
				continue
			}
			tcp := tcpLayer.(*layers.TCP)
			m.assembler.AssembleWithTimestamp(
				pkt.NetworkLayer().NetworkFlow(),
				tcp,
				pkt.Metadata().Timestamp,
			)
		case <-flushTicker.C:
			m.assembler.FlushOlderThan(time.Now().Add(-flushInterval))
		}
	}
}

func (m *Manager) registerStream(netFlow, tcpFlow gopacket.Flow) (uint64, *StreamData) {
	key := makeFlowKey(netFlow, tcpFlow)
	reverseKey := makeFlowKey(netFlow.Reverse(), tcpFlow.Reverse())

	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if reverse direction already created a stream
	if id, ok := m.lookupMap[reverseKey]; ok {
		return id, m.streams[id]
	}

	m.nextID++
	id := m.nextID

	sd := &StreamData{
		ID:        id,
		SrcAddr:   netFlow.Src().String(),
		DstAddr:   netFlow.Dst().String(),
		SrcPort:   uint16(tcpFlow.Src().EndpointType()),
		DstPort:   uint16(tcpFlow.Dst().EndpointType()),
		StartTime: time.Now(),
		LastSeen:  time.Now(),
	}

	m.streams[id] = sd
	m.lookupMap[key] = id

	return id, sd
}

func (m *Manager) appendData(id uint64, netFlow gopacket.Flow, data []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()

	sd, ok := m.streams[id]
	if !ok {
		return
	}

	sd.LastSeen = time.Now()

	// Determine direction: if netFlow.Src matches stored SrcAddr, it's client data
	isClient := netFlow.Src().String() == sd.SrcAddr

	if isClient {
		sd.ClientData = appendCapped(sd.ClientData, data, maxStreamBuffer)
	} else {
		sd.ServerData = appendCapped(sd.ServerData, data, maxStreamBuffer)
	}

	// Try HTTP parse on first data
	if sd.HTTPInfo == nil && len(sd.ClientData) > 0 {
		if tx, err := tryParseHTTP(sd.ClientData, sd.ServerData); err == nil && tx != nil {
			sd.HTTPInfo = tx
		}
	}
}

func appendCapped(buf, data []byte, cap int) []byte {
	remaining := cap - len(buf)
	if remaining <= 0 {
		return buf
	}
	if len(data) > remaining {
		data = data[:remaining]
	}
	return append(buf, data...)
}

// sniffoxStreamFactory creates streams for the TCP assembler.
type sniffoxStreamFactory struct {
	mgr *Manager
}

func (f *sniffoxStreamFactory) New(netFlow, tcpFlow gopacket.Flow) tcpassembly.Stream {
	id, _ := f.mgr.registerStream(netFlow, tcpFlow)

	reader := tcpreader.NewReaderStream()
	s := &sniffoxStream{
		id:      id,
		mgr:     f.mgr,
		netFlow: netFlow,
		reader:  &reader,
	}

	go s.readLoop()
	return &reader
}

type sniffoxStream struct {
	id      uint64
	mgr     *Manager
	netFlow gopacket.Flow
	reader  *tcpreader.ReaderStream
}

func (s *sniffoxStream) readLoop() {
	buf := make([]byte, 4096)
	for {
		n, err := s.reader.Read(buf)
		if n > 0 {
			data := make([]byte, n)
			copy(data, buf[:n])
			s.mgr.appendData(s.id, s.netFlow, data)
		}
		if err != nil {
			return
		}
	}
}

// Reset clears all stream data.
func (m *Manager) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.streams = make(map[uint64]*StreamData)
	m.lookupMap = make(map[flowKey]uint64)
	m.nextID = 0
}

