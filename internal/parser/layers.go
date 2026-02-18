package parser

import (
	"fmt"
	"net"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"sniffox/internal/models"
)

func extractLayers(pkt gopacket.Packet) []models.LayerDetail {
	var result []models.LayerDetail
	for _, layer := range pkt.Layers() {
		if detail, ok := parseLayer(layer, pkt); ok {
			result = append(result, detail)
		}
	}
	return result
}

func parseLayer(layer gopacket.Layer, pkt gopacket.Packet) (models.LayerDetail, bool) {
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
	case *layers.ICMPv6:
		return parseICMPv6(l), true
	case *layers.DNS:
		return parseDNS(l), true
	case *layers.Dot1Q:
		return parseVLAN(l), true
	case *layers.DHCPv4:
		return parseDHCPv4(l), true
	case *layers.NTP:
		return parseNTP(l), true
	case *layers.TLS:
		return parseTLS(l, pkt), true
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

func parseICMPv6(icmp *layers.ICMPv6) models.LayerDetail {
	return models.LayerDetail{
		Name: "ICMPv6",
		Fields: []models.LayerField{
			{Name: "Type", Value: icmp.TypeCode.String()},
			{Name: "Checksum", Value: fmt.Sprintf("0x%04x", icmp.Checksum)},
		},
	}
}

func parseVLAN(vlan *layers.Dot1Q) models.LayerDetail {
	return models.LayerDetail{
		Name: "802.1Q VLAN",
		Fields: []models.LayerField{
			{Name: "VLAN ID", Value: fmt.Sprintf("%d", vlan.VLANIdentifier)},
			{Name: "Priority", Value: fmt.Sprintf("%d", vlan.Priority)},
			{Name: "Drop Eligible", Value: boolToStr(vlan.DropEligible, "Yes", "No")},
			{Name: "Type", Value: vlan.Type.String()},
		},
	}
}

func parseDHCPv4(dhcp *layers.DHCPv4) models.LayerDetail {
	op := "Unknown"
	switch dhcp.Operation {
	case layers.DHCPOpRequest:
		op = "Request (1)"
	case layers.DHCPOpReply:
		op = "Reply (2)"
	}

	fields := []models.LayerField{
		{Name: "Operation", Value: op},
		{Name: "Hardware Type", Value: fmt.Sprintf("%d", dhcp.HardwareType)},
		{Name: "Hardware Len", Value: fmt.Sprintf("%d", dhcp.HardwareLen)},
		{Name: "Transaction ID", Value: fmt.Sprintf("0x%08x", dhcp.Xid)},
		{Name: "Client IP", Value: dhcp.ClientIP.String()},
		{Name: "Your IP", Value: dhcp.YourClientIP.String()},
		{Name: "Server IP", Value: dhcp.NextServerIP.String()},
		{Name: "Client MAC", Value: net.HardwareAddr(dhcp.ClientHWAddr).String()},
	}

	// Extract key options
	for _, opt := range dhcp.Options {
		switch opt.Type {
		case layers.DHCPOptMessageType:
			if len(opt.Data) > 0 {
				msgType := dhcpMsgType(opt.Data[0])
				fields = append(fields, models.LayerField{Name: "Message Type", Value: msgType})
			}
		case layers.DHCPOptRequestIP:
			if len(opt.Data) == 4 {
				fields = append(fields, models.LayerField{
					Name:  "Requested IP",
					Value: net.IP(opt.Data).String(),
				})
			}
		case layers.DHCPOptHostname:
			fields = append(fields, models.LayerField{Name: "Hostname", Value: string(opt.Data)})
		case layers.DHCPOptServerID:
			if len(opt.Data) == 4 {
				fields = append(fields, models.LayerField{
					Name:  "Server ID",
					Value: net.IP(opt.Data).String(),
				})
			}
		}
	}

	return models.LayerDetail{Name: "DHCPv4", Fields: fields}
}

func dhcpMsgType(b byte) string {
	switch layers.DHCPMsgType(b) {
	case layers.DHCPMsgTypeDiscover:
		return "Discover (1)"
	case layers.DHCPMsgTypeOffer:
		return "Offer (2)"
	case layers.DHCPMsgTypeRequest:
		return "Request (3)"
	case layers.DHCPMsgTypeDecline:
		return "Decline (4)"
	case layers.DHCPMsgTypeAck:
		return "ACK (5)"
	case layers.DHCPMsgTypeNak:
		return "NAK (6)"
	case layers.DHCPMsgTypeRelease:
		return "Release (7)"
	case layers.DHCPMsgTypeInform:
		return "Inform (8)"
	default:
		return fmt.Sprintf("Unknown (%d)", b)
	}
}

func parseNTP(ntp *layers.NTP) models.LayerDetail {
	mode := "Unknown"
	switch ntp.Mode {
	case 1:
		mode = "Symmetric Active"
	case 2:
		mode = "Symmetric Passive"
	case 3:
		mode = "Client"
	case 4:
		mode = "Server"
	case 5:
		mode = "Broadcast"
	case 6:
		mode = "Control"
	case 7:
		mode = "Private"
	}

	return models.LayerDetail{
		Name: "NTP",
		Fields: []models.LayerField{
			{Name: "Version", Value: fmt.Sprintf("%d", ntp.Version)},
			{Name: "Mode", Value: fmt.Sprintf("%s (%d)", mode, ntp.Mode)},
			{Name: "Stratum", Value: fmt.Sprintf("%d", ntp.Stratum)},
			{Name: "Poll Interval", Value: fmt.Sprintf("%d", ntp.Poll)},
			{Name: "Precision", Value: fmt.Sprintf("%d", ntp.Precision)},
			{Name: "Root Delay", Value: fmt.Sprintf("%d", ntp.RootDelay)},
			{Name: "Root Dispersion", Value: fmt.Sprintf("%d", ntp.RootDispersion)},
			{Name: "Reference Timestamp", Value: fmt.Sprintf("%v", ntp.ReferenceTimestamp)},
			{Name: "Origin Timestamp", Value: fmt.Sprintf("%v", ntp.OriginTimestamp)},
			{Name: "Receive Timestamp", Value: fmt.Sprintf("%v", ntp.ReceiveTimestamp)},
			{Name: "Transmit Timestamp", Value: fmt.Sprintf("%v", ntp.TransmitTimestamp)},
		},
	}
}

func parseTLS(tls *layers.TLS, pkt gopacket.Packet) models.LayerDetail {
	contentType := "Unknown"
	version := "Unknown"

	if len(tls.Contents) > 0 {
		// First byte is content type
		switch tls.Contents[0] {
		case 20:
			contentType = "ChangeCipherSpec"
		case 21:
			contentType = "Alert"
		case 22:
			contentType = "Handshake"
		case 23:
			contentType = "Application Data"
		}
	}

	if len(tls.Contents) >= 3 {
		v := uint16(tls.Contents[1])<<8 | uint16(tls.Contents[2])
		version = tlsVersionString(v)
	}

	// Try to extract ClientHello details from raw packet data
	// Look for TLS record in the raw data
	var rawData []byte
	if appLayer := pkt.ApplicationLayer(); appLayer != nil {
		rawData = appLayer.LayerContents()
	}
	if len(rawData) == 0 {
		rawData = tls.Contents
	}

	return buildTLSLayerDetail(contentType, version, rawData)
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

	// Check for TLS
	if tlsLayer := pkt.Layer(layers.LayerTypeTLS); tlsLayer != nil {
		protocol = "TLS"
		tls := tlsLayer.(*layers.TLS)
		if len(tls.Contents) > 0 {
			switch tls.Contents[0] {
			case 22:
				info = "Handshake"
				// Try to get SNI
				var rawData []byte
				if appLayer := pkt.ApplicationLayer(); appLayer != nil {
					rawData = appLayer.LayerContents()
				}
				if len(rawData) == 0 {
					rawData = tls.Contents
				}
				hello := parseTLSClientHello(rawData)
				if hello != nil && hello.SNI != "" {
					info = fmt.Sprintf("Client Hello, SNI=%s", hello.SNI)
				}
			case 23:
				info = "Application Data"
			case 20:
				info = "Change Cipher Spec"
			case 21:
				info = "Alert"
			}
		}
	}

	// Check for HTTP (in payload)
	if appLayer := pkt.ApplicationLayer(); appLayer != nil && protocol == "Unknown" {
		if isHTTP(appLayer.Payload()) {
			protocol = "HTTP"
			text := string(appLayer.Payload())
			lines := strings.SplitN(text, "\r\n", 2)
			if len(lines) > 0 {
				info = lines[0]
			}
		}
	}

	// NTP
	if ntpLayer := pkt.Layer(layers.LayerTypeNTP); ntpLayer != nil && protocol == "Unknown" {
		ntp := ntpLayer.(*layers.NTP)
		protocol = "NTP"
		mode := "Unknown"
		switch ntp.Mode {
		case 3:
			mode = "Client"
		case 4:
			mode = "Server"
		case 5:
			mode = "Broadcast"
		default:
			mode = fmt.Sprintf("Mode %d", ntp.Mode)
		}
		info = fmt.Sprintf("NTPv%d %s Stratum=%d", ntp.Version, mode, ntp.Stratum)
	}

	// DHCPv4
	if dhcpLayer := pkt.Layer(layers.LayerTypeDHCPv4); dhcpLayer != nil && protocol == "Unknown" {
		dhcp := dhcpLayer.(*layers.DHCPv4)
		protocol = "DHCP"
		msgType := "Unknown"
		for _, opt := range dhcp.Options {
			if opt.Type == layers.DHCPOptMessageType && len(opt.Data) > 0 {
				msgType = dhcpMsgType(opt.Data[0])
				break
			}
		}
		info = fmt.Sprintf("DHCP %s XID=0x%08x", msgType, dhcp.Xid)
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

	// ICMPv6
	if icmpv6Layer := pkt.Layer(layers.LayerTypeICMPv6); icmpv6Layer != nil && protocol == "Unknown" {
		icmpv6 := icmpv6Layer.(*layers.ICMPv6)
		protocol = "ICMPv6"
		info = icmpv6.TypeCode.String()
	}

	// ICMPv4
	if icmpLayer := pkt.Layer(layers.LayerTypeICMPv4); icmpLayer != nil && protocol == "Unknown" {
		icmp := icmpLayer.(*layers.ICMPv4)
		protocol = "ICMP"
		info = icmp.TypeCode.String()
	}

	// VLAN
	if vlanLayer := pkt.Layer(layers.LayerTypeDot1Q); vlanLayer != nil {
		vlan := vlanLayer.(*layers.Dot1Q)
		if protocol == "Unknown" {
			protocol = "VLAN"
		}
		info = fmt.Sprintf("VLAN %d: %s", vlan.VLANIdentifier, info)
	}

	// TCP
	if tcpLayer := pkt.Layer(layers.LayerTypeTCP); tcpLayer != nil && (protocol == "Unknown" || protocol == "HTTP" || protocol == "TLS") {
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
