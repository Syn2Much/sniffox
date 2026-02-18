package models

import "encoding/json"

// WSMessage is the envelope for all WebSocket communication.
type WSMessage struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// StartCaptureRequest is sent by the client to begin a live capture.
type StartCaptureRequest struct {
	Interface string `json:"interface"`
	BPFFilter string `json:"bpfFilter,omitempty"`
	SnapLen   int    `json:"snapLen,omitempty"`
}

// InterfaceInfo describes a network interface available for capture.
type InterfaceInfo struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Addresses   []string `json:"addresses"`
}

// CaptureStats reports capture statistics.
type CaptureStats struct {
	PacketCount   int `json:"packetCount"`
	DroppedCount  int `json:"droppedCount"`
	InterfaceName string `json:"interfaceName"`
}

// ErrorPayload describes an error sent to the client.
type ErrorPayload struct {
	Message string `json:"message"`
}
