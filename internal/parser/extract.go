package parser

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"sniffox/internal/flow"
)

// FlowTuple holds the extracted 5-tuple + TCP flags from a packet.
type FlowTuple struct {
	SrcIP    string
	DstIP    string
	SrcPort  uint16
	DstPort  uint16
	Protocol string
	Flags    flow.TCPFlags
	Valid    bool
}

// ExtractFlowTuple extracts the flow 5-tuple and TCP flags from a packet
// without re-doing full parsing.
func ExtractFlowTuple(pkt gopacket.Packet) FlowTuple {
	var t FlowTuple

	// IPv4
	if ip4Layer := pkt.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
		ip4 := ip4Layer.(*layers.IPv4)
		t.SrcIP = ip4.SrcIP.String()
		t.DstIP = ip4.DstIP.String()
		t.Protocol = ip4.Protocol.String()
		t.Valid = true
	}

	// IPv6
	if ip6Layer := pkt.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
		ip6 := ip6Layer.(*layers.IPv6)
		t.SrcIP = ip6.SrcIP.String()
		t.DstIP = ip6.DstIP.String()
		t.Protocol = ip6.NextHeader.String()
		t.Valid = true
	}

	// TCP
	if tcpLayer := pkt.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		t.SrcPort = uint16(tcp.SrcPort)
		t.DstPort = uint16(tcp.DstPort)
		t.Protocol = "TCP"
		t.Flags = flow.TCPFlags{
			SYN: tcp.SYN,
			ACK: tcp.ACK,
			FIN: tcp.FIN,
			RST: tcp.RST,
			PSH: tcp.PSH,
		}
	}

	// UDP
	if udpLayer := pkt.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		t.SrcPort = uint16(udp.SrcPort)
		t.DstPort = uint16(udp.DstPort)
		t.Protocol = "UDP"
	}

	// SCTP
	if sctpLayer := pkt.Layer(layers.LayerTypeSCTP); sctpLayer != nil {
		sctp := sctpLayer.(*layers.SCTP)
		t.SrcPort = uint16(sctp.SrcPort)
		t.DstPort = uint16(sctp.DstPort)
		t.Protocol = "SCTP"
	}

	return t
}
