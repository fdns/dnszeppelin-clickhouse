package godnscapture

import (
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	mkdns "github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"net"
	"testing"
	"time"
)

/* Helpers */

func generateUDPPacket(payload []byte) gopacket.Packet {
	var options gopacket.SerializeOptions
	options.FixLengths = true
	buffer := gopacket.NewSerializeBuffer()

	ethernetLayer := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xFF, 0xAA, 0xFA, 0xAA, 0xFF, 0xAA},
		DstMAC:       net.HardwareAddr{0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ipLayer := &layers.IPv4{
		Version:  4,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.IP{127, 0, 0, 1},
		DstIP:    net.IP{8, 8, 8, 8},
	}

	udpLayer := &layers.UDP{
		SrcPort: 53,
		DstPort: 53,
	}

	gopacket.SerializeLayers(buffer, options,
		ethernetLayer,
		ipLayer,
		udpLayer,
		gopacket.Payload(payload),
	)
	return gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Lazy)
}

func packTCP(payload []byte, seq uint32, syn bool) gopacket.Packet {
	// Generate the packet
	var options gopacket.SerializeOptions
	options.FixLengths = true
	buffer := gopacket.NewSerializeBuffer()

	ethernetLayer := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xFF, 0xAA, 0xFA, 0xAA, 0xFF, 0xAA},
		DstMAC:       net.HardwareAddr{0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ipLayer := &layers.IPv4{
		Version:  4,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.IP{127, 0, 0, 1},
		DstIP:    net.IP{8, 8, 8, 8},
	}

	tcpLayer := &layers.TCP{
		Seq:     seq,
		SYN:     syn,
		SrcPort: layers.TCPPort(53),
		DstPort: layers.TCPPort(53),
	}

	gopacket.SerializeLayers(buffer, options,
		ethernetLayer,
		ipLayer,
		tcpLayer,
		gopacket.Payload(payload),
	)
	return gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Lazy)

}

func readResultOrTiemout(data chan DNSResult) (*DNSResult, error) {
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	select {
	case packet := <-data:
		return &packet, nil
	case <-timer.C:
		return nil, fmt.Errorf("Result read timeout")
	}
}

func TestCaptureDNSParse(t *testing.T) {
	t.Parallel()
	rChannel, capturer := createDefaultCapturer()
	defer close(capturer.options.Done)

	data := new(mkdns.Msg)
	data.SetQuestion("example.com.", mkdns.TypeA)
	pack, _ := data.Pack()

	capturer.processing <- generateUDPPacket(pack)
	result, err := readResultOrTiemout(rChannel)
	if assert.NoError(t, err) {
		assert.Equal(t, 1, len(result.DNS.Question), "DNS Question decoded incorrectly")
		assert.Equal(t, "example.com.", result.DNS.Question[0].Name, "DNS Question decoded incorrectly")
		assert.Equal(t, mkdns.TypeA, result.DNS.Question[0].Qtype, "DNS Question decoded incorrectly")
	}
}

func TestCaptureIP4(t *testing.T) {
	t.Parallel()
	rChannel, capturer := createDefaultCapturer()
	defer close(capturer.options.Done)
	defer close(rChannel)

	data := new(mkdns.Msg)
	data.SetQuestion("example.com.", mkdns.TypeA)
	pack, _ := data.Pack()

	capturer.processing <- generateUDPPacket(pack)
	result, err := readResultOrTiemout(rChannel)
	if assert.NoError(t, err) {
		assert.Equal(t, uint8(4), result.IPVersion, "DNS IP Version parsed incorrectly")
		assert.Equal(t, net.IPv4(127, 0, 0, 1)[12:], result.SrcIP, "DNS Source IP parsed incorrectly")
		assert.Equal(t, net.IPv4(8, 8, 8, 8)[12:], result.DstIP, "DNS Dest IP parsed incorrectly")
		assert.Equal(t, "udp", result.Protocol, "DNS Dest IP parsed incorrectly")
		assert.Equal(t, uint16(len(pack)), result.PacketLength, "DNS Dest IP parsed incorrectly")
	}
}

func TestCaptureFragmentedIP4(t *testing.T) {
	t.Parallel()
	rChannel, capturer := createDefaultCapturer()
	defer close(capturer.options.Done)
	defer close(rChannel)

	data := new(mkdns.Msg)
	data.SetQuestion("example.com.", mkdns.TypeA)
	pack, _ := data.Pack()

	// Generate the udp packet
	var options gopacket.SerializeOptions
	options.FixLengths = true
	buffer := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, options,
		&layers.UDP{
			SrcPort: 53,
			DstPort: 53,
		},
		gopacket.Payload(pack),
	)
	udpPacket := buffer.Bytes()

	// Generate the fragmented ip packets
	a := udpPacket[:16]
	b := udpPacket[16:]
	// Send a
	buffer = gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, options,
		&layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0xFF, 0xAA, 0xFA, 0xAA, 0xFF, 0xAA},
			DstMAC:       net.HardwareAddr{0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD},
			EthernetType: layers.EthernetTypeIPv4,
		},
		&layers.IPv4{
			Version:  4,
			Protocol: layers.IPProtocolUDP,
			SrcIP:    net.IP{127, 0, 0, 1},
			DstIP:    net.IP{8, 8, 8, 8},
			Flags:    layers.IPv4MoreFragments,
		},
		gopacket.Payload(a),
	)
	capturer.processing <- gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Lazy)
	// Send b
	buffer = gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, options,
		&layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0xFF, 0xAA, 0xFA, 0xAA, 0xFF, 0xAA},
			DstMAC:       net.HardwareAddr{0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD},
			EthernetType: layers.EthernetTypeIPv4,
		},
		&layers.IPv4{
			Version:    4,
			Protocol:   layers.IPProtocolUDP,
			SrcIP:      net.IP{127, 0, 0, 1},
			DstIP:      net.IP{8, 8, 8, 8},
			Flags:      0,
			FragOffset: 2,
		},
		gopacket.Payload(b),
	)
	capturer.processing <- gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Lazy)

	result, err := readResultOrTiemout(rChannel)
	if assert.NoError(t, err) {
		assert.Equal(t, net.IPv4(127, 0, 0, 1)[12:], result.SrcIP, "DNS Source IP parsed incorrectly")
		assert.Equal(t, net.IPv4(8, 8, 8, 8)[12:], result.DstIP, "DNS Dest IP parsed incorrectly")
		assert.Equal(t, uint8(4), result.IPVersion, "DNS Dest IP parsed incorrectly")
		assert.Equal(t, "udp", result.Protocol, "DNS Dest IP parsed incorrectly")
		assert.Equal(t, uint16(len(pack)), result.PacketLength, "DNS Dest IP parsed incorrectly")
	}
}

func TestCaptureIP6(t *testing.T) {
	t.Parallel()
	rChannel, capturer := createDefaultCapturer()
	defer close(capturer.options.Done)
	defer close(rChannel)

	data := new(mkdns.Msg)
	data.SetQuestion("example.com.", mkdns.TypeA)
	pack, _ := data.Pack()

	// Generate the packet
	var options gopacket.SerializeOptions
	options.FixLengths = true
	buffer := gopacket.NewSerializeBuffer()

	gopacket.SerializeLayers(buffer, options,
		&layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0xFF, 0xAA, 0xFA, 0xAA, 0xFF, 0xAA},
			DstMAC:       net.HardwareAddr{0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD},
			EthernetType: layers.EthernetTypeIPv6,
		},
		&layers.IPv6{
			Version:    6,
			NextHeader: layers.IPProtocolUDP,
			SrcIP:      net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			DstIP:      net.IP{32, 1, 72, 96, 72, 96, 0, 0, 0, 0, 0, 0, 0, 0, 136, 136},
		},
		&layers.UDP{
			SrcPort: layers.UDPPort(53),
			DstPort: layers.UDPPort(53),
		},
		gopacket.Payload(pack),
	)

	capturer.processing <- gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Lazy)
	result, err := readResultOrTiemout(rChannel)
	if assert.NoError(t, err) {
		assert.Equal(t, uint8(6), result.IPVersion, "DNS IP Version parsed incorrectly")
		assert.Equal(t, net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, result.SrcIP, "DNS Source IP parsed incorrectly")
		assert.Equal(t, net.IP{32, 1, 72, 96, 72, 96, 0, 0, 0, 0, 0, 0, 0, 0, 136, 136}, result.DstIP, "DNS Dest IP parsed incorrectly")
		assert.Equal(t, "udp", result.Protocol, "DNS Dest IP parsed incorrectly")
		assert.Equal(t, uint16(len(pack)), result.PacketLength, "DNS Dest IP parsed incorrectly")
		assert.Equal(t, 1, len(result.DNS.Question), "IPv6 dns question have unexpected count")
		assert.Equal(t, "example.com.", result.DNS.Question[0].Name, "IPv6 dns question parsed incorrectly")
	}
}

func TestCaptureIP6Fragmented(t *testing.T) {
	t.Parallel()
	rChannel, capturer := createDefaultCapturer()
	defer close(capturer.options.Done)
	defer close(rChannel)

	data := new(mkdns.Msg)
	data.SetQuestion("example.com.", mkdns.TypeA)
	pack, _ := data.Pack()

	// Generate the udp packet
	var options gopacket.SerializeOptions
	options.FixLengths = true
	buffer := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, options,
		&layers.UDP{
			SrcPort: 53,
			DstPort: 53,
		},
		gopacket.Payload(pack),
	)
	udpPacket := buffer.Bytes()

	// Generate the fragmented ip packets
	a := udpPacket[:16]
	b := udpPacket[16:]

	// Generate the fragment header manually
	frag := make([]byte, 8)
	frag[0] = 17 // UDP
	frag[3] = 1  // MoreFragments

	// Send a
	buffer = gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, options,
		&layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0xFF, 0xAA, 0xFA, 0xAA, 0xFF, 0xAA},
			DstMAC:       net.HardwareAddr{0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD},
			EthernetType: layers.EthernetTypeIPv6,
		},
		&layers.IPv6{
			Version:    6,
			NextHeader: layers.IPProtocolIPv6Fragment,
			SrcIP:      net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			DstIP:      net.IP{32, 1, 72, 96, 72, 96, 0, 0, 0, 0, 0, 0, 0, 0, 136, 136},
		},
		gopacket.Payload(frag),
		gopacket.Payload(a),
	)

	capturer.processing <- gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Lazy)

	// Send b
	frag[3] = byte(uint(2) << 3) // Offset 1
	buffer = gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, options,
		&layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0xFF, 0xAA, 0xFA, 0xAA, 0xFF, 0xAA},
			DstMAC:       net.HardwareAddr{0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD},
			EthernetType: layers.EthernetTypeIPv6,
		},
		&layers.IPv6{
			Version:    6,
			NextHeader: layers.IPProtocolIPv6Fragment,
			SrcIP:      net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			DstIP:      net.IP{32, 1, 72, 96, 72, 96, 0, 0, 0, 0, 0, 0, 0, 0, 136, 136},
		},
		gopacket.Payload(frag),
		gopacket.Payload(b),
	)

	capturer.processing <- gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Lazy)

	result, err := readResultOrTiemout(rChannel)

	if assert.NoError(t, err) {
		assert.Equal(t, uint8(6), result.IPVersion, "DNS IP Version parsed incorrectly")
		assert.Equal(t, net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, result.SrcIP, "DNS Source IP parsed incorrectly")
		assert.Equal(t, net.IP{32, 1, 72, 96, 72, 96, 0, 0, 0, 0, 0, 0, 0, 0, 136, 136}, result.DstIP, "DNS Dest IP parsed incorrectly")
		assert.Equal(t, "udp", result.Protocol, "DNS Dest IP parsed incorrectly")
		assert.Equal(t, uint16(len(pack)), result.PacketLength, "DNS Dest IP parsed incorrectly")
		assert.Equal(t, 1, len(result.DNS.Question), "IPv6 dns question have unexpected count")
		assert.Equal(t, "example.com.", result.DNS.Question[0].Name, "IPv6 dns question parsed incorrectly")
	}
}

func TestCaptureTCP(t *testing.T) {
	t.Parallel()

	// Generate the data
	data := new(mkdns.Msg)
	data.SetQuestion("example.com.", mkdns.TypeA)
	payload, _ := data.Pack()

	buf := []byte{0, 0}
	binary.BigEndian.PutUint16(buf, uint16(len(payload)))
	buf = append(buf, payload...)
	packet := packTCP(buf, 1, true)

	// Send the packet
	rChannel, capturer := createDefaultCapturer()
	defer close(capturer.options.Done)
	defer close(rChannel)
	capturer.processing <- packet
	result, err := readResultOrTiemout(rChannel)
	if assert.NoError(t, err) {
		assert.Equal(t, 1, len(result.DNS.Question), "TCP Question decoded incorrectly")
		assert.Equal(t, uint8(4), result.IPVersion, "DNS Dest IP parsed incorrectly")
		assert.Equal(t, "tcp", result.Protocol, "DNS Dest IP parsed incorrectly")
		assert.Equal(t, uint16(len(payload)), result.PacketLength, "DNS Dest IP parsed incorrectly")
	}
}

func TestCaptureTCPDivided(t *testing.T) {
	t.Parallel()

	// Generate the data
	data := new(mkdns.Msg)
	data.SetQuestion("example.com.", mkdns.TypeA)
	payload, _ := data.Pack()

	buf := []byte{0, 0}
	binary.BigEndian.PutUint16(buf, uint16(len(payload)))
	buf = append(buf, payload...)

	a := buf[:len(buf)/2]
	b := buf[len(buf)/2:]
	packetA := packTCP(a, 10, true)
	packetB := packTCP(b, 10+uint32(len(a))+1, false)
	//return

	// Send the packet
	rChannel, capturer := createDefaultCapturer()
	defer close(capturer.options.Done)
	defer close(rChannel)
	capturer.processing <- packetB
	capturer.processing <- packetA
	result, err := readResultOrTiemout(rChannel)
	if assert.NoError(t, err) {
		assert.Equal(t, 1, len(result.DNS.Question), "TCP Question decoded incorrectly")
	}
}
