package engine

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/gopacket"

	"dumptcp/internal/capture"
	"dumptcp/internal/models"
	"dumptcp/internal/parser"
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
}

// New creates a new Engine.
func New() *Engine {
	return &Engine{
		clients: make(map[Client]bool),
	}
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

	e.mu.Lock()
	e.liveCapture = lc
	e.capturing = true
	e.pktCount = 0
	e.startTime = time.Now()
	e.stopCh = make(chan struct{})
	e.mu.Unlock()

	payload, _ := json.Marshal(map[string]string{"interfaceName": req.Interface})
	e.broadcast(models.WSMessage{Type: "capture_started", Payload: payload})

	go e.captureLoop(lc.Packets())

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
	e.mu.Unlock()

	// Broadcast immediately so clients get instant feedback
	e.broadcast(models.WSMessage{Type: "capture_stopped"})

	// Then clean up — handle.Close() may block briefly until the
	// pending pcap read returns, but the client already knows we stopped.
	close(stopCh)
	lc.Close()
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
		e.mu.Unlock()

		info := parser.Parse(pkt, num, startTime)
		payload, _ := json.Marshal(info)
		e.broadcast(models.WSMessage{Type: "packet", Payload: payload})
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
