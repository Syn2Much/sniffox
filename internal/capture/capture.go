package capture

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

const (
	DefaultSnapLen = 65535
	DefaultTimeout = 100 * time.Millisecond
)

// LiveCapture manages a live packet capture session.
type LiveCapture struct {
	handle *pcap.Handle
	iface  string
}

// InterfaceInfo describes a network interface.
type InterfaceInfo struct {
	Name        string
	Description string
	Addresses   []string
}

// ListInterfaces returns all available capture interfaces.
func ListInterfaces() ([]InterfaceInfo, error) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}
	var out []InterfaceInfo
	for _, d := range devs {
		info := InterfaceInfo{
			Name:        d.Name,
			Description: d.Description,
		}
		for _, addr := range d.Addresses {
			info.Addresses = append(info.Addresses, addr.IP.String())
		}
		out = append(out, info)
	}
	return out, nil
}

// NewLiveCapture opens a live capture on the given interface.
func NewLiveCapture(iface, bpfFilter string, snapLen int) (*LiveCapture, error) {
	if snapLen <= 0 {
		snapLen = DefaultSnapLen
	}
	handle, err := pcap.OpenLive(iface, int32(snapLen), true, DefaultTimeout)
	if err != nil {
		return nil, fmt.Errorf("open live capture on %s: %w", iface, err)
	}
	if bpfFilter != "" {
		if err := handle.SetBPFFilter(bpfFilter); err != nil {
			handle.Close()
			return nil, fmt.Errorf("set BPF filter %q: %w", bpfFilter, err)
		}
	}
	return &LiveCapture{handle: handle, iface: iface}, nil
}

// Packets returns a gopacket.PacketSource to iterate packets.
func (lc *LiveCapture) Packets() *gopacket.PacketSource {
	return gopacket.NewPacketSource(lc.handle, lc.handle.LinkType())
}

// Interface returns the interface name.
func (lc *LiveCapture) Interface() string {
	return lc.iface
}

// Stats returns capture statistics.
func (lc *LiveCapture) Stats() (received, dropped int, err error) {
	stats, err := lc.handle.Stats()
	if err != nil {
		return 0, 0, err
	}
	return stats.PacketsReceived, stats.PacketsDropped, nil
}

// Close stops the capture.
func (lc *LiveCapture) Close() {
	if lc.handle != nil {
		lc.handle.Close()
	}
}
