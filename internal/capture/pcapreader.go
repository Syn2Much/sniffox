package capture

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// PcapReader reads packets from a .pcap file.
type PcapReader struct {
	handle *pcap.Handle
}

// NewPcapReader opens a pcap file for reading.
func NewPcapReader(path string) (*PcapReader, error) {
	handle, err := pcap.OpenOffline(path)
	if err != nil {
		return nil, fmt.Errorf("open pcap file %q: %w", path, err)
	}
	return &PcapReader{handle: handle}, nil
}

// Packets returns a gopacket.PacketSource for the file.
func (pr *PcapReader) Packets() *gopacket.PacketSource {
	return gopacket.NewPacketSource(pr.handle, pr.handle.LinkType())
}

// LinkType returns the link layer type for the pcap file.
func (pr *PcapReader) LinkType() layers.LinkType {
	return pr.handle.LinkType()
}

// Close releases the handle.
func (pr *PcapReader) Close() {
	if pr.handle != nil {
		pr.handle.Close()
	}
}
