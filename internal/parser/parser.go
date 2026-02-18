package parser

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/gopacket"

	"sniffox/internal/models"
)

// Parse converts a raw gopacket.Packet into a PacketInfo.
func Parse(pkt gopacket.Packet, number int, startTime time.Time) models.PacketInfo {
	info := models.PacketInfo{
		Number: number,
		Length: pkt.Metadata().Length,
	}

	// Timestamp relative to start
	ts := pkt.Metadata().Timestamp
	if startTime.IsZero() {
		info.Timestamp = ts.Format("15:04:05.000000")
	} else {
		elapsed := ts.Sub(startTime)
		info.Timestamp = fmt.Sprintf("%.6f", elapsed.Seconds())
	}

	// Extract layers
	info.Layers = extractLayers(pkt)

	// Determine protocol, addresses, info summary
	info.Protocol, info.SrcAddr, info.DstAddr, info.Info = summarize(pkt)

	// Hex dump
	if data := pkt.Data(); len(data) > 0 {
		info.HexDump = formatHexDump(data)
		info.RawHex = formatRawHex(data)
	}

	return info
}

func formatHexDump(data []byte) string {
	var sb strings.Builder
	for offset := 0; offset < len(data); offset += 16 {
		// Offset
		sb.WriteString(fmt.Sprintf("%04x  ", offset))

		// Hex bytes
		end := offset + 16
		if end > len(data) {
			end = len(data)
		}
		for i := offset; i < offset+16; i++ {
			if i < end {
				sb.WriteString(fmt.Sprintf("%02x ", data[i]))
			} else {
				sb.WriteString("   ")
			}
			if i == offset+7 {
				sb.WriteByte(' ')
			}
		}
		sb.WriteString(" |")

		// ASCII
		for i := offset; i < end; i++ {
			b := data[i]
			if b >= 0x20 && b <= 0x7e {
				sb.WriteByte(b)
			} else {
				sb.WriteByte('.')
			}
		}
		sb.WriteByte('|')
		sb.WriteByte('\n')
	}
	return sb.String()
}

func formatRawHex(data []byte) string {
	var sb strings.Builder
	for _, b := range data {
		sb.WriteString(fmt.Sprintf("%02x", b))
	}
	return sb.String()
}
