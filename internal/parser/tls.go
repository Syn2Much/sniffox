package parser

import (
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"

	"sniffox/internal/models"
)

// TLS ClientHello manual byte parser.
// gopacket decodes TLS records but not handshake internals.

// TLSClientHelloInfo holds extracted ClientHello fields.
type TLSClientHelloInfo struct {
	SNI             string
	CipherSuites    []uint16
	Version         uint16
	Extensions      []uint16
	SupportedGroups []uint16
	ECPointFormats  []uint8
	JA3Hash         string
}

// parseTLSClientHello parses a TLS ClientHello from raw handshake data.
func parseTLSClientHello(data []byte) *TLSClientHelloInfo {
	info := &TLSClientHelloInfo{}

	if len(data) < 44 {
		return nil
	}

	if data[0] != 0x16 {
		return nil
	}

	recordLen := int(binary.BigEndian.Uint16(data[3:5]))
	pos := 5

	if len(data) < pos+recordLen {
		if len(data) < pos+4 {
			return nil
		}
	}

	if data[pos] != 0x01 {
		return nil
	}
	pos += 4

	if len(data) < pos+2 {
		return info
	}

	info.Version = binary.BigEndian.Uint16(data[pos : pos+2])
	pos += 2

	if len(data) < pos+32 {
		return info
	}
	pos += 32

	if len(data) < pos+1 {
		return info
	}
	sessionIDLen := int(data[pos])
	pos++
	if len(data) < pos+sessionIDLen {
		return info
	}
	pos += sessionIDLen

	if len(data) < pos+2 {
		return info
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2
	if len(data) < pos+cipherSuitesLen {
		cipherSuitesLen = len(data) - pos
	}
	for i := 0; i+1 < cipherSuitesLen; i += 2 {
		cs := binary.BigEndian.Uint16(data[pos+i : pos+i+2])
		info.CipherSuites = append(info.CipherSuites, cs)
	}
	pos += cipherSuitesLen

	if len(data) < pos+1 {
		return info
	}
	compLen := int(data[pos])
	pos++
	if len(data) < pos+compLen {
		return info
	}
	pos += compLen

	if len(data) < pos+2 {
		info.JA3Hash = computeJA3(info)
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

		info.Extensions = append(info.Extensions, extType)

		// SNI extension (type 0x0000)
		if extType == 0x0000 && extDataLen >= 5 {
			sniData := data[pos : pos+extDataLen]
			if len(sniData) >= 5 {
				nameLen := int(binary.BigEndian.Uint16(sniData[3:5]))
				if 5+nameLen <= len(sniData) {
					info.SNI = string(sniData[5 : 5+nameLen])
				}
			}
		}

		// Supported Groups (type 0x000a)
		if extType == 0x000a && extDataLen >= 2 {
			groupData := data[pos : pos+extDataLen]
			groupListLen := int(binary.BigEndian.Uint16(groupData[0:2]))
			gPos := 2
			for gPos+1 < 2+groupListLen && gPos+1 < len(groupData) {
				group := binary.BigEndian.Uint16(groupData[gPos : gPos+2])
				info.SupportedGroups = append(info.SupportedGroups, group)
				gPos += 2
			}
		}

		// EC Point Formats (type 0x000b)
		if extType == 0x000b && extDataLen >= 1 {
			fmtData := data[pos : pos+extDataLen]
			fmtLen := int(fmtData[0])
			for j := 1; j <= fmtLen && j < len(fmtData); j++ {
				info.ECPointFormats = append(info.ECPointFormats, fmtData[j])
			}
		}

		pos += extDataLen
	}

	info.JA3Hash = computeJA3(info)
	return info
}

// isGREASE returns true if the value is a GREASE value (RFC 8701).
func isGREASE(val uint16) bool {
	return (val & 0x0f0f) == 0x0a0a
}

// computeJA3 computes JA3 hash: MD5 of "version,ciphers,extensions,curves,formats"
func computeJA3(info *TLSClientHelloInfo) string {
	if info == nil || info.Version == 0 {
		return ""
	}

	// Filter GREASE from cipher suites
	var ciphers []string
	for _, cs := range info.CipherSuites {
		if !isGREASE(cs) {
			ciphers = append(ciphers, fmt.Sprintf("%d", cs))
		}
	}

	// Filter GREASE from extensions
	var exts []string
	for _, ext := range info.Extensions {
		if !isGREASE(ext) {
			exts = append(exts, fmt.Sprintf("%d", ext))
		}
	}

	// Filter GREASE from supported groups
	var groups []string
	for _, g := range info.SupportedGroups {
		if !isGREASE(g) {
			groups = append(groups, fmt.Sprintf("%d", g))
		}
	}

	// EC point formats (no GREASE filtering needed)
	var formats []string
	for _, f := range info.ECPointFormats {
		formats = append(formats, fmt.Sprintf("%d", f))
	}

	ja3String := fmt.Sprintf("%d,%s,%s,%s,%s",
		info.Version,
		strings.Join(ciphers, "-"),
		strings.Join(exts, "-"),
		strings.Join(groups, "-"),
		strings.Join(formats, "-"),
	)

	hash := md5.Sum([]byte(ja3String))
	return fmt.Sprintf("%x", hash)
}

// Cipher suite name lookup
var cipherSuiteNames = map[uint16]string{
	0x1301: "TLS_AES_128_GCM_SHA256",
	0x1302: "TLS_AES_256_GCM_SHA384",
	0x1303: "TLS_CHACHA20_POLY1305_SHA256",
	0xc02c: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	0xc02b: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	0xc030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	0xc02f: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	0xcca9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
	0xcca8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	0xc024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
	0xc023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
	0xc028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
	0xc027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
	0xc014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
	0xc013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
	0x009d: "TLS_RSA_WITH_AES_256_GCM_SHA384",
	0x009c: "TLS_RSA_WITH_AES_128_GCM_SHA256",
	0x003d: "TLS_RSA_WITH_AES_256_CBC_SHA256",
	0x003c: "TLS_RSA_WITH_AES_128_CBC_SHA256",
	0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
	0x002f: "TLS_RSA_WITH_AES_128_CBC_SHA",
	0x00ff: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
	0x5600: "TLS_FALLBACK_SCSV",
	0x00a8: "TLS_PSK_WITH_AES_128_GCM_SHA256",
	0x00a9: "TLS_PSK_WITH_AES_256_GCM_SHA384",
	0xccab: "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256",
	0xc0a3: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
	0xc09f: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
	0xc09e: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
}

func cipherSuiteName(cs uint16) string {
	if name, ok := cipherSuiteNames[cs]; ok {
		return name
	}
	return fmt.Sprintf("0x%04x", cs)
}

// buildTLSLayerDetail builds a LayerDetail from gopacket TLS layer + raw data.
func buildTLSLayerDetail(contentType string, version string, rawData []byte) models.LayerDetail {
	fields := []models.LayerField{
		{Name: "Content Type", Value: contentType},
		{Name: "Version", Value: version},
	}

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
			// Show named cipher suites
			named := make([]string, 0, len(hello.CipherSuites))
			for _, cs := range hello.CipherSuites {
				if !isGREASE(cs) {
					named = append(named, cipherSuiteName(cs))
				}
			}
			// Sort to keep display consistent
			sort.Strings(named)
			display := strings.Join(named, ", ")
			if len(display) > 300 {
				display = display[:300] + "..."
			}
			fields = append(fields, models.LayerField{
				Name:  "Cipher Suites",
				Value: fmt.Sprintf("%d suites: %s", len(hello.CipherSuites), display),
			})
		}
		if hello.JA3Hash != "" {
			fields = append(fields, models.LayerField{
				Name:  "JA3 Fingerprint",
				Value: hello.JA3Hash,
			})
		}
		if len(hello.Extensions) > 0 {
			extStrs := make([]string, 0, len(hello.Extensions))
			for _, ext := range hello.Extensions {
				if !isGREASE(ext) {
					extStrs = append(extStrs, fmt.Sprintf("%d", ext))
				}
			}
			fields = append(fields, models.LayerField{
				Name:  "Extensions",
				Value: strings.Join(extStrs, ", "),
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
