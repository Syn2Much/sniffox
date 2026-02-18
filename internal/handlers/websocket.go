package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/websocket"

	"sniffox/internal/engine"
	"sniffox/internal/models"
)

const (
	writeWait  = 5 * time.Second
	sendBuffer = 512 // buffered channel size — drops when full
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

// WSClient wraps a WebSocket connection and implements engine.Client.
type WSClient struct {
	conn   *websocket.Conn
	eng    *engine.Engine
	sendCh chan models.WSMessage
	done   chan struct{}
}

// NewWSClient creates a WSClient and registers it with the engine.
func NewWSClient(conn *websocket.Conn, eng *engine.Engine) *WSClient {
	c := &WSClient{
		conn:   conn,
		eng:    eng,
		sendCh: make(chan models.WSMessage, sendBuffer),
		done:   make(chan struct{}),
	}
	eng.RegisterClient(c)
	go c.writeLoop()
	return c
}

// SendMessage queues a message for async delivery. Non-blocking: drops if buffer full.
func (c *WSClient) SendMessage(msg models.WSMessage) error {
	select {
	case c.sendCh <- msg:
		return nil
	default:
		// Buffer full — drop the packet to avoid blocking the capture goroutine.
		// Control messages (non-packet) get priority retry.
		if msg.Type != "packet" {
			// Force-send control messages by draining one old packet
			select {
			case <-c.sendCh:
				c.sendCh <- msg
			default:
				// Channel was drained between checks — just send
				select {
				case c.sendCh <- msg:
				default:
				}
			}
		}
		return nil
	}
}

// writeLoop drains the send channel and writes to the WebSocket.
func (c *WSClient) writeLoop() {
	defer c.conn.Close()
	for {
		select {
		case msg, ok := <-c.sendCh:
			if !ok {
				return
			}
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteJSON(msg); err != nil {
				return
			}

			// Drain and batch-send any queued messages in a single write burst
			n := len(c.sendCh)
			for i := 0; i < n; i++ {
				msg = <-c.sendCh
				c.conn.SetWriteDeadline(time.Now().Add(writeWait))
				if err := c.conn.WriteJSON(msg); err != nil {
					return
				}
			}
		case <-c.done:
			return
		}
	}
}

// ReadLoop reads messages from the client and dispatches commands.
func (c *WSClient) ReadLoop() {
	defer func() {
		c.eng.UnregisterClient(c)
		close(c.done)
		close(c.sendCh)
	}()

	for {
		_, raw, err := c.conn.ReadMessage()
		if err != nil {
			return
		}
		var msg models.WSMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			c.sendError("invalid message format")
			continue
		}
		c.handleCommand(msg)
	}
}

func (c *WSClient) handleCommand(msg models.WSMessage) {
	switch msg.Type {
	case "get_interfaces":
		ifaces, err := c.eng.GetInterfaces()
		if err != nil {
			c.sendError("failed to list interfaces: " + err.Error())
			return
		}
		payload, _ := json.Marshal(ifaces)
		c.SendMessage(models.WSMessage{Type: "interfaces", Payload: payload})

	case "start_capture":
		var req models.StartCaptureRequest
		if err := json.Unmarshal(msg.Payload, &req); err != nil {
			c.sendError("invalid start_capture payload")
			return
		}
		if err := c.eng.StartCapture(req); err != nil {
			c.sendError("capture failed: " + err.Error())
			return
		}

	case "stop_capture":
		c.eng.StopCapture()

	default:
		c.sendError("unknown command: " + msg.Type)
	}
}

func (c *WSClient) sendError(message string) {
	payload, _ := json.Marshal(models.ErrorPayload{Message: message})
	c.SendMessage(models.WSMessage{Type: "error", Payload: payload})
}

// HandleWebSocket is the HTTP handler for WebSocket upgrades.
func HandleWebSocket(eng *engine.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("WebSocket upgrade error: %v", err)
			return
		}
		client := NewWSClient(conn, eng)
		client.ReadLoop()
	}
}
