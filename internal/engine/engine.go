package engine

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"sniffox/internal/capture"
	"sniffox/internal/flow"
	"sniffox/internal/models"
	"sniffox/internal/parser"
	"sniffox/internal/stream"
)

// Client represents a connected WebSocket client that receives packets.
type Client interface {
	SendMessage(msg models.WSMessage) error
}

// Engine manages capture sessions and broadcasts packets to clients.
type Engine struct {
	mu          sync.Mutex
	clients     map[Client]bool
	liveCapture *capture.LiveCapture
	stopCh      chan struct{}
	capturing   bool
	pktCount    int
	startTime   time.Time

	flowTracker *flow.Tracker
	streamMgr   *stream.Manager
}

// New creates a new Engine.
func New() *Engine {
	e := &Engine{
		clients:     make(map[Client]bool),
		flowTracker: flow.NewTracker(),
	}
	return e
}

// RegisterClient adds a client to receive packet broadcasts.
func (e *Engine) RegisterClient(c Client) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.clients[c] = true
}

// UnregisterClient removes a client.
func (e *Engine) UnregisterClient(c Client) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.clients, c)
}

// GetInterfaces returns available network interfaces.
func (e *Engine) GetInterfaces() ([]models.InterfaceInfo, error) {
	ifaces, err := capture.ListInterfaces()
	if err != nil {
		return nil, err
	}
	var out []models.InterfaceInfo
	for _, i := range ifaces {
		out = append(out, models.InterfaceInfo{
			Name:        i.Name,
			Description: i.Description,
			Addresses:   i.Addresses,
		})
	}
	return out, nil
}

// StartCapture begins a live capture on the given interface.
func (e *Engine) StartCapture(req models.StartCaptureRequest) error {
	e.mu.Lock()
	if e.capturing {
		e.mu.Unlock()
		return fmt.Errorf("capture already running")
	}
	e.mu.Unlock()

	lc, err := capture.NewLiveCapture(req.Interface, req.BPFFilter, req.SnapLen)
	if err != nil {
		return err
	}

	// Create and start stream manager
	smgr := stream.NewManager(e)
	smgr.Start()

	e.mu.Lock()
	e.liveCapture = lc
	e.capturing = true
	e.pktCount = 0
	e.startTime = time.Now()
	e.stopCh = make(chan struct{})
	e.streamMgr = smgr
	e.flowTracker.Reset()
	e.mu.Unlock()

	payload, _ := json.Marshal(map[string]string{"interfaceName": req.Interface})
	e.broadcast(models.WSMessage{Type: "capture_started", Payload: payload})

	go e.captureLoop(lc.Packets())
	go e.startFlowBroadcaster()

	return nil
}

// StopCapture stops the active capture.
func (e *Engine) StopCapture() {
	e.mu.Lock()
	if !e.capturing {
		e.mu.Unlock()
		return
	}
	e.capturing = false
	stopCh := e.stopCh
	lc := e.liveCapture
	smgr := e.streamMgr
	e.mu.Unlock()

	// Broadcast immediately so clients get instant feedback
	e.broadcast(models.WSMessage{Type: "capture_stopped"})

	// Then clean up — handle.Close() may block briefly until the
	// pending pcap read returns, but the client already knows we stopped.
	close(stopCh)
	lc.Close()

	if smgr != nil {
		smgr.Stop()
	}
}

// LoadPcapFile reads a pcap file and streams packets to all clients with pacing.
func (e *Engine) LoadPcapFile(path string) error {
	reader, err := capture.NewPcapReader(path)
	if err != nil {
		return err
	}
	defer reader.Close()

	e.mu.Lock()
	e.pktCount = 0
	e.startTime = time.Time{}
	e.flowTracker.Reset()
	e.mu.Unlock()

	source := reader.Packets()
	var firstTS time.Time
	batch := 0
	for pkt := range source.Packets() {
		if firstTS.IsZero() {
			firstTS = pkt.Metadata().Timestamp
		}

		e.mu.Lock()
		e.pktCount++
		num := e.pktCount
		e.mu.Unlock()

		info := parser.Parse(pkt, num, firstTS)

		// Flow tracking for pcap files too
		tuple := parser.ExtractFlowTuple(pkt)
		if tuple.Valid {
			flowID, _ := e.flowTracker.Track(tuple.SrcIP, tuple.DstIP, tuple.SrcPort, tuple.DstPort, tuple.Protocol, info.Length, tuple.Flags)
			info.FlowID = flowID
		}

		payload, _ := json.Marshal(info)
		e.broadcast(models.WSMessage{Type: "packet", Payload: payload})

		// Pace: yield every 200 packets so the client can breathe
		batch++
		if batch >= 200 {
			batch = 0
			time.Sleep(5 * time.Millisecond)
		}
	}

	return nil
}

// GetFlows returns the current flow table.
func (e *Engine) GetFlows() []*flow.Flow {
	return e.flowTracker.GetFlows()
}

// GetStreamData returns reassembled stream data by ID.
func (e *Engine) GetStreamData(id uint64) *stream.StreamDataResponse {
	e.mu.Lock()
	smgr := e.streamMgr
	e.mu.Unlock()

	if smgr == nil {
		return nil
	}
	return smgr.GetStreamData(id)
}

// BroadcastStreamEvent implements stream.Broadcaster.
func (e *Engine) BroadcastStreamEvent(eventType string, payload json.RawMessage) {
	evt := models.StreamEvent{
		EventType: eventType,
		Data:      payload,
	}
	data, _ := json.Marshal(evt)
	e.broadcast(models.WSMessage{Type: "stream_event", Payload: data})
}

func (e *Engine) captureLoop(source *gopacket.PacketSource) {
	for {
		select {
		case <-e.stopCh:
			return
		default:
		}

		pkt, err := source.NextPacket()
		if err != nil {
			select {
			case <-e.stopCh:
				return
			default:
			}
			log.Printf("Packet read error: %v", err)
			continue
		}

		e.mu.Lock()
		e.pktCount++
		num := e.pktCount
		startTime := e.startTime
		smgr := e.streamMgr
		e.mu.Unlock()

		info := parser.Parse(pkt, num, startTime)

		// Flow tracking
		tuple := parser.ExtractFlowTuple(pkt)
		if tuple.Valid {
			flowID, _ := e.flowTracker.Track(tuple.SrcIP, tuple.DstIP, tuple.SrcPort, tuple.DstPort, tuple.Protocol, info.Length, tuple.Flags)
			info.FlowID = flowID
		}

		// Stream reassembly — feed TCP packets
		if tcpLayer := pkt.Layer(layers.LayerTypeTCP); tcpLayer != nil && smgr != nil {
			smgr.Feed(pkt)

			// Look up stream ID
			if pkt.NetworkLayer() != nil {
				streamID := smgr.GetStreamID(pkt.NetworkLayer().NetworkFlow(), tcpLayer.(*layers.TCP).TransportFlow())
				if streamID > 0 {
					info.StreamID = streamID
				}
			}
		}

		payload, _ := json.Marshal(info)
		e.broadcast(models.WSMessage{Type: "packet", Payload: payload})
	}
}

// startFlowBroadcaster ticks every 1s and broadcasts the flow table.
func (e *Engine) startFlowBroadcaster() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-e.stopCh:
			return
		case <-ticker.C:
			flows := e.flowTracker.GetFlows()
			if len(flows) == 0 {
				continue
			}

			// Convert to FlowInfo
			infos := make([]models.FlowInfo, 0, len(flows))
			for _, f := range flows {
				infos = append(infos, models.FlowInfo{
					ID:          f.ID,
					SrcIP:       f.SrcIP,
					DstIP:       f.DstIP,
					SrcPort:     f.SrcPort,
					DstPort:     f.DstPort,
					Protocol:    f.Protocol,
					PacketCount: f.PacketCount,
					ByteCount:   f.ByteCount,
					FirstSeen:   f.FirstSeen,
					LastSeen:    f.LastSeen,
					TCPState:    string(f.TCPState),
					FwdPackets:  f.FwdPackets,
					FwdBytes:    f.FwdBytes,
					RevPackets:  f.RevPackets,
					RevBytes:    f.RevBytes,
				})
			}

			payload, _ := json.Marshal(infos)
			e.broadcast(models.WSMessage{Type: "flow_update", Payload: payload})
		}
	}
}

func (e *Engine) broadcast(msg models.WSMessage) {
	e.mu.Lock()
	clients := make([]Client, 0, len(e.clients))
	for c := range e.clients {
		clients = append(clients, c)
	}
	e.mu.Unlock()

	for _, c := range clients {
		c.SendMessage(msg)
	}
}
