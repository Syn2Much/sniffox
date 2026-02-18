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
	PacketCount   int    `json:"packetCount"`
	DroppedCount  int    `json:"droppedCount"`
	InterfaceName string `json:"interfaceName"`
}

// ErrorPayload describes an error sent to the client.
type ErrorPayload struct {
	Message string `json:"message"`
}

// FlowInfo is sent in flow_update broadcasts.
type FlowInfo struct {
	ID          uint64 `json:"id"`
	SrcIP       string `json:"srcIp"`
	DstIP       string `json:"dstIp"`
	SrcPort     uint16 `json:"srcPort"`
	DstPort     uint16 `json:"dstPort"`
	Protocol    string `json:"protocol"`
	PacketCount int    `json:"packetCount"`
	ByteCount   int64  `json:"byteCount"`
	FirstSeen   int64  `json:"firstSeen"`
	LastSeen    int64  `json:"lastSeen"`
	TCPState    string `json:"tcpState,omitempty"`
	FwdPackets  int    `json:"fwdPackets"`
	FwdBytes    int64  `json:"fwdBytes"`
	RevPackets  int    `json:"revPackets"`
	RevBytes    int64  `json:"revBytes"`
}

// StreamEvent is sent for stream-related WebSocket events.
type StreamEvent struct {
	EventType string          `json:"eventType"` // stream_start, stream_data
	StreamID  uint64          `json:"streamId"`
	SrcAddr   string          `json:"srcAddr,omitempty"`
	DstAddr   string          `json:"dstAddr,omitempty"`
	Data      json.RawMessage `json:"data,omitempty"`
}

// GetStreamDataRequest is sent by the client to request stream data.
type GetStreamDataRequest struct {
	StreamID uint64 `json:"streamId"`
}

// GetFlowsRequest is sent by the client to request the flow table.
type GetFlowsRequest struct{}
