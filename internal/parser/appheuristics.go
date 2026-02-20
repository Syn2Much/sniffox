package parser

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/google/gopacket"

	"sniffox/internal/models"
)

// detectAppProtocol attempts heuristic detection of application-layer protocols
// from raw payload data. Called from parseLayer's default case.
func detectAppProtocol(data []byte, pkt gopacket.Packet) (models.LayerDetail, bool) {
	if len(data) < 4 {
		return models.LayerDetail{}, false
	}

	// SSH: payload starts with "SSH-"
	if isSSH(data) {
		return parseSSH(data), true
	}

	// QUIC: UDP 443 + long header bit
	if getTransportProto(pkt) == "UDP" && portIs(pkt, 443) && isQUIC(data) {
		return parseQUIC(data), true
	}

	// MQTT: TCP 1883/8883 + CONNECT packet signature
	if getTransportProto(pkt) == "TCP" && portIsAny(pkt, 1883, 8883) && isMQTT(data) {
		return parseMQTT(data), true
	}

	// SIP: UDP 5060 + starts with SIP method/response
	if portIsAny(pkt, 5060, 5061) && isSIP(data) {
		return parseSIP(data), true
	}

	// Modbus: TCP 502 + protocol ID 0x0000
	if getTransportProto(pkt) == "TCP" && portIs(pkt, 502) && isModbus(data) {
		return parseModbus(data), true
	}

	// RDP: TCP 3389 + TPKT version 3
	if getTransportProto(pkt) == "TCP" && portIs(pkt, 3389) && isRDP(data) {
		return parseRDP(data), true
	}

	return models.LayerDetail{}, false
}

// detectAppProtocolSummary returns protocol name and info for summarize().
func detectAppProtocolSummary(data []byte, pkt gopacket.Packet) (string, string) {
	if len(data) < 4 {
		return "", ""
	}

	if isSSH(data) {
		ver := extractSSHVersion(data)
		return "SSH", fmt.Sprintf("Version: %s", ver)
	}

	if getTransportProto(pkt) == "UDP" && portIs(pkt, 443) && isQUIC(data) {
		return "QUIC", "QUIC Connection"
	}

	if getTransportProto(pkt) == "TCP" && portIsAny(pkt, 1883, 8883) && isMQTT(data) {
		return "MQTT", "MQTT CONNECT"
	}

	if portIsAny(pkt, 5060, 5061) && isSIP(data) {
		method := sipMethod(data)
		return "SIP", method
	}

	if getTransportProto(pkt) == "TCP" && portIs(pkt, 502) && isModbus(data) {
		if len(data) >= 8 {
			fc := data[7]
			return "Modbus", fmt.Sprintf("Function Code %d", fc)
		}
		return "Modbus", "Modbus/TCP"
	}

	if getTransportProto(pkt) == "TCP" && portIs(pkt, 3389) && isRDP(data) {
		return "RDP", "TPKT/RDP Connection"
	}

	return "", ""
}

// ==================== SSH Detection ====================

func isSSH(data []byte) bool {
	return len(data) >= 4 && bytes.HasPrefix(data, []byte("SSH-"))
}

func extractSSHVersion(data []byte) string {
	end := bytes.IndexByte(data, '\n')
	if end < 0 {
		if len(data) > 80 {
			return string(data[:80])
		}
		return string(data)
	}
	line := strings.TrimRight(string(data[:end]), "\r\n")
	return line
}

func parseSSH(data []byte) models.LayerDetail {
	version := extractSSHVersion(data)
	fields := []models.LayerField{
		{Name: "Version String", Value: version},
	}

	// Parse "SSH-2.0-OpenSSH_8.9" format
	parts := strings.SplitN(version, "-", 3)
	if len(parts) >= 3 {
		fields = append(fields, models.LayerField{Name: "Protocol Version", Value: parts[0] + "-" + parts[1]})
		fields = append(fields, models.LayerField{Name: "Software", Value: parts[2]})
	}

	return models.LayerDetail{Name: "SSH", Fields: fields}
}

// ==================== QUIC Detection ====================

func isQUIC(data []byte) bool {
	// QUIC long header: first bit is 1, and we need at least some bytes
	return len(data) >= 5 && (data[0]&0x80) != 0
}

func parseQUIC(data []byte) models.LayerDetail {
	fields := []models.LayerField{
		{Name: "Header Form", Value: "Long Header"},
	}

	if len(data) >= 5 {
		version := bytesToUint32BE(data[1:5])
		fields = append(fields, models.LayerField{
			Name:  "Version",
			Value: quicVersionString(version),
		})
	}

	if len(data) >= 6 {
		dcidLen := int(data[5])
		fields = append(fields, models.LayerField{
			Name:  "DCID Length",
			Value: fmt.Sprintf("%d", dcidLen),
		})
		if dcidLen > 0 && len(data) >= 6+dcidLen {
			fields = append(fields, models.LayerField{
				Name:  "Destination CID",
				Value: hexDCID(data, 6, dcidLen),
			})
		}
	}

	return models.LayerDetail{Name: "QUIC", Fields: fields}
}

// ==================== MQTT Detection ====================

func isMQTT(data []byte) bool {
	// MQTT CONNECT: first byte 0x10, "MQTT" in first 10 bytes
	if len(data) < 10 {
		return false
	}
	if data[0] != 0x10 {
		return false
	}
	return bytes.Contains(data[:10], []byte("MQTT"))
}

func parseMQTT(data []byte) models.LayerDetail {
	fields := []models.LayerField{
		{Name: "Packet Type", Value: "CONNECT"},
	}

	// Find "MQTT" to get protocol level
	idx := bytes.Index(data, []byte("MQTT"))
	if idx >= 0 && idx+5 < len(data) {
		level := data[idx+4]
		fields = append(fields, models.LayerField{
			Name:  "Protocol Level",
			Value: fmt.Sprintf("%d", level),
		})
		if idx+6 < len(data) {
			flags := data[idx+5]
			flagParts := []string{}
			if flags&0x80 != 0 {
				flagParts = append(flagParts, "Username")
			}
			if flags&0x40 != 0 {
				flagParts = append(flagParts, "Password")
			}
			if flags&0x04 != 0 {
				flagParts = append(flagParts, "Will")
			}
			if flags&0x02 != 0 {
				flagParts = append(flagParts, "Clean Session")
			}
			fields = append(fields, models.LayerField{
				Name:  "Connect Flags",
				Value: fmt.Sprintf("0x%02x [%s]", flags, strings.Join(flagParts, ", ")),
			})
		}
	}

	return models.LayerDetail{Name: "MQTT", Fields: fields}
}

// ==================== SIP Detection ====================

func isSIP(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	s := string(data[:8])
	if len(data) < 8 {
		s = string(data)
	}
	return strings.HasPrefix(s, "SIP/") ||
		strings.HasPrefix(s, "INVITE ") ||
		strings.HasPrefix(s, "REGISTER") ||
		strings.HasPrefix(s, "ACK ") ||
		strings.HasPrefix(s, "BYE ") ||
		strings.HasPrefix(s, "CANCEL ") ||
		strings.HasPrefix(s, "OPTIONS ") ||
		strings.HasPrefix(s, "PRACK ") ||
		strings.HasPrefix(s, "NOTIFY ") ||
		strings.HasPrefix(s, "PUBLISH ") ||
		strings.HasPrefix(s, "INFO ") ||
		strings.HasPrefix(s, "REFER ") ||
		strings.HasPrefix(s, "MESSAGE ") ||
		strings.HasPrefix(s, "UPDATE ") ||
		strings.HasPrefix(s, "SUBSCRI")
}

func parseSIP(data []byte) models.LayerDetail {
	line := firstLine(data)
	fields := []models.LayerField{
		{Name: "Request/Status Line", Value: line},
	}

	method := sipMethod(data)
	fields = append(fields, models.LayerField{Name: "Method", Value: method})

	callID := sipHeader(data, "Call-ID")
	if callID == "" {
		callID = sipHeader(data, "i")
	}
	if callID != "" {
		fields = append(fields, models.LayerField{Name: "Call-ID", Value: callID})
	}

	from := sipHeader(data, "From")
	if from != "" {
		fields = append(fields, models.LayerField{Name: "From", Value: from})
	}

	to := sipHeader(data, "To")
	if to != "" {
		fields = append(fields, models.LayerField{Name: "To", Value: to})
	}

	return models.LayerDetail{Name: "SIP", Fields: fields}
}

// ==================== Modbus Detection ====================

func isModbus(data []byte) bool {
	// Modbus/TCP: bytes 2-3 are protocol identifier 0x0000, minimum 8 bytes
	if len(data) < 8 {
		return false
	}
	return data[2] == 0 && data[3] == 0
}

func parseModbus(data []byte) models.LayerDetail {
	fields := []models.LayerField{}

	if len(data) >= 2 {
		txnID := bytesToUint16BE(data[0:2])
		fields = append(fields, models.LayerField{
			Name:  "Transaction ID",
			Value: fmt.Sprintf("0x%04x", txnID),
		})
	}

	if len(data) >= 4 {
		fields = append(fields, models.LayerField{
			Name:  "Protocol ID",
			Value: fmt.Sprintf("0x%04x", bytesToUint16BE(data[2:4])),
		})
	}

	if len(data) >= 6 {
		length := bytesToUint16BE(data[4:6])
		fields = append(fields, models.LayerField{
			Name:  "Length",
			Value: fmt.Sprintf("%d", length),
		})
	}

	if len(data) >= 7 {
		unitID := data[6]
		fields = append(fields, models.LayerField{
			Name:  "Unit ID",
			Value: fmt.Sprintf("%d", unitID),
		})
	}

	if len(data) >= 8 {
		fc := data[7]
		fcName := modbusFunction(fc)
		fields = append(fields, models.LayerField{
			Name:  "Function Code",
			Value: fmt.Sprintf("%d (%s)", fc, fcName),
		})
	}

	return models.LayerDetail{Name: "Modbus", Fields: fields}
}

func modbusFunction(fc byte) string {
	switch fc {
	case 1:
		return "Read Coils"
	case 2:
		return "Read Discrete Inputs"
	case 3:
		return "Read Holding Registers"
	case 4:
		return "Read Input Registers"
	case 5:
		return "Write Single Coil"
	case 6:
		return "Write Single Register"
	case 15:
		return "Write Multiple Coils"
	case 16:
		return "Write Multiple Registers"
	default:
		return "Unknown"
	}
}

// ==================== RDP Detection ====================

func isRDP(data []byte) bool {
	// TPKT: version 3
	return len(data) >= 4 && data[0] == 3
}

func parseRDP(data []byte) models.LayerDetail {
	fields := []models.LayerField{
		{Name: "TPKT Version", Value: fmt.Sprintf("%d", data[0])},
	}

	if len(data) >= 4 {
		length := bytesToUint16BE(data[2:4])
		fields = append(fields, models.LayerField{
			Name:  "TPKT Length",
			Value: fmt.Sprintf("%d", length),
		})
	}

	if len(data) >= 5 {
		fields = append(fields, models.LayerField{
			Name:  "X.224 Length",
			Value: fmt.Sprintf("%d", data[4]),
		})
	}

	if len(data) >= 6 {
		pduType := "Unknown"
		switch data[5] {
		case 0xe0:
			pduType = "Connection Request"
		case 0xd0:
			pduType = "Connection Confirm"
		case 0x80:
			pduType = "Disconnect Request"
		case 0xf0:
			pduType = "Data Transfer"
		default:
			pduType = fmt.Sprintf("0x%02x", data[5])
		}
		fields = append(fields, models.LayerField{
			Name:  "X.224 PDU Type",
			Value: pduType,
		})
	}

	return models.LayerDetail{Name: "RDP", Fields: fields}
}
