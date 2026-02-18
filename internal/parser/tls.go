package parser

import (
	"encoding/binary"
	"fmt"
	"strings"

	"sniffox/internal/models"
)

// TLS ClientHello manual byte parser.
// gopacket decodes TLS records but not handshake internals.

// TLSClientHelloInfo holds extracted ClientHello fields.
type TLSClientHelloInfo struct {
	SNI          string
	CipherSuites []uint16
	Version      uint16
}

// parseTLSClientHello parses a TLS ClientHello from raw handshake data.
// Returns partial results on malformed data.
func parseTLSClientHello(data []byte) *TLSClientHelloInfo {
	info := &TLSClientHelloInfo{}

	// Minimum: 5 byte record header + 4 byte handshake header + 2 version + 32 random + 1 session len
	if len(data) < 44 {
		return nil
	}

	// TLS record header
	// ContentType(1) Version(2) Length(2)
	if data[0] != 0x16 { // Handshake
		return nil
	}

	recordLen := int(binary.BigEndian.Uint16(data[3:5]))
	pos := 5

	if len(data) < pos+recordLen {
		// Truncated, work with what we have
		if len(data) < pos+4 {
			return nil
		}
	}

	// Handshake header
	if data[pos] != 0x01 { // ClientHello
		return nil
	}
	pos += 4 // type(1) + length(3)

	if len(data) < pos+2 {
		return info
	}

	// Client version
	info.Version = binary.BigEndian.Uint16(data[pos : pos+2])
	pos += 2

	// Random (32 bytes)
	if len(data) < pos+32 {
		return info
	}
	pos += 32

	// Session ID
	if len(data) < pos+1 {
		return info
	}
	sessionIDLen := int(data[pos])
	pos++
	if len(data) < pos+sessionIDLen {
		return info
	}
	pos += sessionIDLen

	// Cipher suites
	if len(data) < pos+2 {
		return info
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2
	if len(data) < pos+cipherSuitesLen {
		// Parse what we can
		cipherSuitesLen = len(data) - pos
	}
	for i := 0; i+1 < cipherSuitesLen; i += 2 {
		cs := binary.BigEndian.Uint16(data[pos+i : pos+i+2])
		info.CipherSuites = append(info.CipherSuites, cs)
	}
	pos += cipherSuitesLen

	// Compression methods
	if len(data) < pos+1 {
		return info
	}
	compLen := int(data[pos])
	pos++
	if len(data) < pos+compLen {
		return info
	}
	pos += compLen

	// Extensions
	if len(data) < pos+2 {
		return info
	}
	extLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2
	extEnd := pos + extLen
	if extEnd > len(data) {
		extEnd = len(data)
	}

	for pos+4 <= extEnd {
		extType := binary.BigEndian.Uint16(data[pos : pos+2])
		extDataLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		pos += 4

		if pos+extDataLen > extEnd {
			break
		}

		// SNI extension (type 0x0000)
		if extType == 0x0000 && extDataLen >= 5 {
			sniData := data[pos : pos+extDataLen]
			// SNI list length (2) + type (1) + name length (2) + name
			if len(sniData) >= 5 {
				nameLen := int(binary.BigEndian.Uint16(sniData[3:5]))
				if 5+nameLen <= len(sniData) {
					info.SNI = string(sniData[5 : 5+nameLen])
				}
			}
		}

		pos += extDataLen
	}

	return info
}

// buildTLSLayerDetail builds a LayerDetail from gopacket TLS layer + raw data.
func buildTLSLayerDetail(contentType string, version string, rawData []byte) models.LayerDetail {
	fields := []models.LayerField{
		{Name: "Content Type", Value: contentType},
		{Name: "Version", Value: version},
	}

	// Try to parse ClientHello from raw packet data
	hello := parseTLSClientHello(rawData)
	if hello != nil {
		if hello.SNI != "" {
			fields = append(fields, models.LayerField{Name: "SNI", Value: hello.SNI})
		}
		fields = append(fields, models.LayerField{
			Name:  "Client Version",
			Value: tlsVersionString(hello.Version),
		})
		if len(hello.CipherSuites) > 0 {
			suites := make([]string, 0, len(hello.CipherSuites))
			for _, cs := range hello.CipherSuites {
				suites = append(suites, fmt.Sprintf("0x%04x", cs))
			}
			display := strings.Join(suites, ", ")
			if len(display) > 200 {
				display = display[:200] + "..."
			}
			fields = append(fields, models.LayerField{
				Name:  "Cipher Suites",
				Value: fmt.Sprintf("%d suites: %s", len(hello.CipherSuites), display),
			})
		}
	}

	return models.LayerDetail{Name: "TLS", Fields: fields}
}

func tlsVersionString(v uint16) string {
	switch v {
	case 0x0301:
		return "TLS 1.0"
	case 0x0302:
		return "TLS 1.1"
	case 0x0303:
		return "TLS 1.2"
	case 0x0304:
		return "TLS 1.3"
	case 0x0300:
		return "SSL 3.0"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}
