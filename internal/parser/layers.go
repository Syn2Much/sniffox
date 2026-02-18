package parser

import (
	"fmt"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"dumptcp/internal/models"
)

func extractLayers(pkt gopacket.Packet) []models.LayerDetail {
	var result []models.LayerDetail
	for _, layer := range pkt.Layers() {
		if detail, ok := parseLayer(layer); ok {
			result = append(result, detail)
		}
	}
	return result
}

func parseLayer(layer gopacket.Layer) (models.LayerDetail, bool) {
	switch l := layer.(type) {
	case *layers.Ethernet:
		return parseEthernet(l), true
	case *layers.ARP:
		return parseARP(l), true
	case *layers.IPv4:
		return parseIPv4(l), true
	case *layers.IPv6:
		return parseIPv6(l), true
	case *layers.TCP:
		return parseTCP(l), true
	case *layers.UDP:
		return parseUDP(l), true
	case *layers.ICMPv4:
		return parseICMPv4(l), true
	case *layers.DNS:
		return parseDNS(l), true
	default:
		// Generic payload or unknown layer
		if layer.LayerType() == gopacket.LayerTypePayload {
			data := layer.LayerContents()
			if isHTTP(data) {
				return parseHTTP(data), true
			}
		}
		return models.LayerDetail{}, false
	}
}

func parseEthernet(eth *layers.Ethernet) models.LayerDetail {
	return models.LayerDetail{
		Name: "Ethernet II",
		Fields: []models.LayerField{
			{Name: "Source", Value: eth.SrcMAC.String()},
			{Name: "Destination", Value: eth.DstMAC.String()},
			{Name: "Type", Value: eth.EthernetType.String()},
		},
	}
}

func parseARP(arp *layers.ARP) models.LayerDetail {
	op := "Unknown"
	switch arp.Operation {
	case 1:
		op = "Request (1)"
	case 2:
		op = "Reply (2)"
	}
	return models.LayerDetail{
		Name: "ARP",
		Fields: []models.LayerField{
			{Name: "Operation", Value: op},
			{Name: "Sender MAC", Value: fmt.Sprintf("%x", arp.SourceHwAddress)},
			{Name: "Sender IP", Value: fmt.Sprintf("%d.%d.%d.%d", arp.SourceProtAddress[0], arp.SourceProtAddress[1], arp.SourceProtAddress[2], arp.SourceProtAddress[3])},
			{Name: "Target MAC", Value: fmt.Sprintf("%x", arp.DstHwAddress)},
			{Name: "Target IP", Value: fmt.Sprintf("%d.%d.%d.%d", arp.DstProtAddress[0], arp.DstProtAddress[1], arp.DstProtAddress[2], arp.DstProtAddress[3])},
		},
	}
}

func parseIPv4(ip *layers.IPv4) models.LayerDetail {
	return models.LayerDetail{
		Name: "IPv4",
		Fields: []models.LayerField{
			{Name: "Version", Value: fmt.Sprintf("%d", ip.Version)},
			{Name: "Header Length", Value: fmt.Sprintf("%d bytes", ip.IHL*4)},
			{Name: "Type of Service", Value: fmt.Sprintf("0x%02x", ip.TOS)},
			{Name: "Total Length", Value: fmt.Sprintf("%d", ip.Length)},
			{Name: "Identification", Value: fmt.Sprintf("0x%04x (%d)", ip.Id, ip.Id)},
			{Name: "Flags", Value: ip.Flags.String()},
			{Name: "Fragment Offset", Value: fmt.Sprintf("%d", ip.FragOffset)},
			{Name: "TTL", Value: fmt.Sprintf("%d", ip.TTL)},
			{Name: "Protocol", Value: ip.Protocol.String()},
			{Name: "Checksum", Value: fmt.Sprintf("0x%04x", ip.Checksum)},
			{Name: "Source", Value: ip.SrcIP.String()},
			{Name: "Destination", Value: ip.DstIP.String()},
		},
	}
}

func parseIPv6(ip *layers.IPv6) models.LayerDetail {
	return models.LayerDetail{
		Name: "IPv6",
		Fields: []models.LayerField{
			{Name: "Version", Value: fmt.Sprintf("%d", ip.Version)},
			{Name: "Traffic Class", Value: fmt.Sprintf("0x%02x", ip.TrafficClass)},
			{Name: "Flow Label", Value: fmt.Sprintf("0x%05x", ip.FlowLabel)},
			{Name: "Payload Length", Value: fmt.Sprintf("%d", ip.Length)},
			{Name: "Next Header", Value: ip.NextHeader.String()},
			{Name: "Hop Limit", Value: fmt.Sprintf("%d", ip.HopLimit)},
			{Name: "Source", Value: ip.SrcIP.String()},
			{Name: "Destination", Value: ip.DstIP.String()},
		},
	}
}

func parseTCP(tcp *layers.TCP) models.LayerDetail {
	flagParts := []string{}
	if tcp.SYN {
		flagParts = append(flagParts, "SYN")
	}
	if tcp.ACK {
		flagParts = append(flagParts, "ACK")
	}
	if tcp.FIN {
		flagParts = append(flagParts, "FIN")
	}
	if tcp.RST {
		flagParts = append(flagParts, "RST")
	}
	if tcp.PSH {
		flagParts = append(flagParts, "PSH")
	}
	if tcp.URG {
		flagParts = append(flagParts, "URG")
	}
	flags := strings.Join(flagParts, ", ")

	return models.LayerDetail{
		Name: "TCP",
		Fields: []models.LayerField{
			{Name: "Source Port", Value: fmt.Sprintf("%d", tcp.SrcPort)},
			{Name: "Destination Port", Value: fmt.Sprintf("%d", tcp.DstPort)},
			{Name: "Sequence Number", Value: fmt.Sprintf("%d", tcp.Seq)},
			{Name: "Acknowledgment Number", Value: fmt.Sprintf("%d", tcp.Ack)},
			{Name: "Data Offset", Value: fmt.Sprintf("%d bytes", tcp.DataOffset*4)},
			{Name: "Flags", Value: fmt.Sprintf("[%s]", flags)},
			{Name: "Window Size", Value: fmt.Sprintf("%d", tcp.Window)},
			{Name: "Checksum", Value: fmt.Sprintf("0x%04x", tcp.Checksum)},
			{Name: "Urgent Pointer", Value: fmt.Sprintf("%d", tcp.Urgent)},
		},
	}
}

func parseUDP(udp *layers.UDP) models.LayerDetail {
	return models.LayerDetail{
		Name: "UDP",
		Fields: []models.LayerField{
			{Name: "Source Port", Value: fmt.Sprintf("%d", udp.SrcPort)},
			{Name: "Destination Port", Value: fmt.Sprintf("%d", udp.DstPort)},
			{Name: "Length", Value: fmt.Sprintf("%d", udp.Length)},
			{Name: "Checksum", Value: fmt.Sprintf("0x%04x", udp.Checksum)},
		},
	}
}

func parseICMPv4(icmp *layers.ICMPv4) models.LayerDetail {
	return models.LayerDetail{
		Name: "ICMPv4",
		Fields: []models.LayerField{
			{Name: "Type", Value: fmt.Sprintf("%d (%s)", icmp.TypeCode.Type(), icmp.TypeCode.String())},
			{Name: "Code", Value: fmt.Sprintf("%d", icmp.TypeCode.Code())},
			{Name: "Checksum", Value: fmt.Sprintf("0x%04x", icmp.Checksum)},
			{Name: "Identifier", Value: fmt.Sprintf("0x%04x", icmp.Id)},
			{Name: "Sequence", Value: fmt.Sprintf("%d", icmp.Seq)},
		},
	}
}

func parseDNS(dns *layers.DNS) models.LayerDetail {
	fields := []models.LayerField{
		{Name: "Transaction ID", Value: fmt.Sprintf("0x%04x", dns.ID)},
		{Name: "QR", Value: boolToStr(dns.QR, "Response", "Query")},
		{Name: "Opcode", Value: fmt.Sprintf("%d", dns.OpCode)},
		{Name: "Questions", Value: fmt.Sprintf("%d", dns.QDCount)},
		{Name: "Answers", Value: fmt.Sprintf("%d", dns.ANCount)},
	}

	// Add questions
	for _, q := range dns.Questions {
		fields = append(fields, models.LayerField{
			Name:  "Query",
			Value: fmt.Sprintf("%s %s %s", string(q.Name), q.Type.String(), q.Class.String()),
		})
	}

	// Add answers
	for _, a := range dns.Answers {
		fields = append(fields, models.LayerField{
			Name:  "Answer",
			Value: fmt.Sprintf("%s -> %s (TTL: %d)", string(a.Name), a.IP.String(), a.TTL),
		})
	}

	return models.LayerDetail{Name: "DNS", Fields: fields}
}

func isHTTP(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	s := string(data[:4])
	return s == "GET " || s == "POST" || s == "PUT " || s == "DELE" ||
		s == "HEAD" || s == "HTTP" || s == "PATC" || s == "OPTI"
}

func parseHTTP(data []byte) models.LayerDetail {
	text := string(data)
	lines := strings.SplitN(text, "\r\n", 32)

	fields := []models.LayerField{}
	if len(lines) > 0 {
		fields = append(fields, models.LayerField{Name: "Request/Status Line", Value: lines[0]})
	}
	for _, line := range lines[1:] {
		if line == "" {
			break
		}
		parts := strings.SplitN(line, ": ", 2)
		if len(parts) == 2 {
			fields = append(fields, models.LayerField{Name: parts[0], Value: parts[1]})
		}
	}

	return models.LayerDetail{Name: "HTTP", Fields: fields}
}

func boolToStr(b bool, t, f string) string {
	if b {
		return t
	}
	return f
}

// summarize determines the highest-level protocol and builds address/info strings.
func summarize(pkt gopacket.Packet) (protocol, src, dst, info string) {
	protocol = "Unknown"
	src = ""
	dst = ""
	info = ""

	// Check for HTTP first (in payload)
	if appLayer := pkt.ApplicationLayer(); appLayer != nil {
		if isHTTP(appLayer.Payload()) {
			protocol = "HTTP"
			text := string(appLayer.Payload())
			lines := strings.SplitN(text, "\r\n", 2)
			if len(lines) > 0 {
				info = lines[0]
			}
		}
	}

	// DNS
	if dnsLayer := pkt.Layer(layers.LayerTypeDNS); dnsLayer != nil {
		dns := dnsLayer.(*layers.DNS)
		protocol = "DNS"
		if dns.QR {
			info = "Standard query response"
		} else {
			info = "Standard query"
		}
		for _, q := range dns.Questions {
			info += " " + string(q.Name) + " " + q.Type.String()
		}
	}

	// ICMPv4
	if icmpLayer := pkt.Layer(layers.LayerTypeICMPv4); icmpLayer != nil && protocol == "Unknown" {
		icmp := icmpLayer.(*layers.ICMPv4)
		protocol = "ICMP"
		info = icmp.TypeCode.String()
	}

	// TCP
	if tcpLayer := pkt.Layer(layers.LayerTypeTCP); tcpLayer != nil && (protocol == "Unknown" || protocol == "HTTP") {
		tcp := tcpLayer.(*layers.TCP)
		if protocol == "Unknown" {
			protocol = "TCP"
		}
		flagParts := []string{}
		if tcp.SYN {
			flagParts = append(flagParts, "SYN")
		}
		if tcp.ACK {
			flagParts = append(flagParts, "ACK")
		}
		if tcp.FIN {
			flagParts = append(flagParts, "FIN")
		}
		if tcp.RST {
			flagParts = append(flagParts, "RST")
		}
		if tcp.PSH {
			flagParts = append(flagParts, "PSH")
		}
		if protocol == "TCP" {
			info = fmt.Sprintf("%d -> %d [%s] Seq=%d Ack=%d Win=%d Len=%d",
				tcp.SrcPort, tcp.DstPort, strings.Join(flagParts, ","),
				tcp.Seq, tcp.Ack, tcp.Window, len(tcp.Payload))
		}
		src = addPort(src, fmt.Sprintf("%d", tcp.SrcPort))
		dst = addPort(dst, fmt.Sprintf("%d", tcp.DstPort))
	}

	// UDP
	if udpLayer := pkt.Layer(layers.LayerTypeUDP); udpLayer != nil && protocol == "Unknown" {
		udp := udpLayer.(*layers.UDP)
		protocol = "UDP"
		info = fmt.Sprintf("%d -> %d Len=%d", udp.SrcPort, udp.DstPort, udp.Length)
		src = addPort(src, fmt.Sprintf("%d", udp.SrcPort))
		dst = addPort(dst, fmt.Sprintf("%d", udp.DstPort))
	}

	// IPv4
	if ip4Layer := pkt.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
		ip4 := ip4Layer.(*layers.IPv4)
		if src == "" || !strings.Contains(src, ":") {
			src = ip4.SrcIP.String() + maybePort(src)
		}
		if dst == "" || !strings.Contains(dst, ":") {
			dst = ip4.DstIP.String() + maybePort(dst)
		}
	}

	// IPv6
	if ip6Layer := pkt.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
		ip6 := ip6Layer.(*layers.IPv6)
		if src == "" || !strings.Contains(src, ":") {
			src = ip6.SrcIP.String() + maybePort(src)
		}
		if dst == "" || !strings.Contains(dst, ":") {
			dst = ip6.DstIP.String() + maybePort(dst)
		}
		if protocol == "Unknown" {
			protocol = "IPv6"
		}
	}

	// ARP
	if arpLayer := pkt.Layer(layers.LayerTypeARP); arpLayer != nil {
		arp := arpLayer.(*layers.ARP)
		protocol = "ARP"
		srcIP := fmt.Sprintf("%d.%d.%d.%d", arp.SourceProtAddress[0], arp.SourceProtAddress[1], arp.SourceProtAddress[2], arp.SourceProtAddress[3])
		dstIP := fmt.Sprintf("%d.%d.%d.%d", arp.DstProtAddress[0], arp.DstProtAddress[1], arp.DstProtAddress[2], arp.DstProtAddress[3])
		src = srcIP
		dst = dstIP
		if arp.Operation == 1 {
			info = fmt.Sprintf("Who has %s? Tell %s", dstIP, srcIP)
		} else {
			info = fmt.Sprintf("%s is at %x", srcIP, arp.SourceHwAddress)
		}
	}

	// Ethernet fallback
	if ethLayer := pkt.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth := ethLayer.(*layers.Ethernet)
		if src == "" {
			src = eth.SrcMAC.String()
		}
		if dst == "" {
			dst = eth.DstMAC.String()
		}
	}

	return
}

func addPort(_, port string) string {
	return ":" + port
}

func maybePort(s string) string {
	if strings.HasPrefix(s, ":") {
		return s
	}
	return ""
}
