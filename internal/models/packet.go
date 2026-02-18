package models

// PacketInfo represents a parsed packet with all display data.
type PacketInfo struct {
	Number    int           `json:"number"`
	Timestamp string        `json:"timestamp"`
	SrcAddr   string        `json:"srcAddr"`
	DstAddr   string        `json:"dstAddr"`
	Protocol  string        `json:"protocol"`
	Length    int           `json:"length"`
	Info      string        `json:"info"`
	Layers    []LayerDetail `json:"layers"`
	HexDump   string        `json:"hexDump"`
	RawHex    string        `json:"rawHex"`
	FlowID    uint64        `json:"flowId,omitempty"`
	StreamID  uint64        `json:"streamId,omitempty"`
}

// LayerDetail represents one protocol layer in the packet.
type LayerDetail struct {
	Name   string       `json:"name"`
	Fields []LayerField `json:"fields"`
}

// LayerField represents a single field within a protocol layer.
type LayerField struct {
	Name     string       `json:"name"`
	Value    string       `json:"value"`
	Children []LayerField `json:"children,omitempty"`
}
