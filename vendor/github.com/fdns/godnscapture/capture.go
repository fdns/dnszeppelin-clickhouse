package godnscapture

import (
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	mkdns "github.com/miekg/dns"
	"net"
	"os"
	"os/signal"
)

type CaptureOptions struct {
	DevName                      string
	Filter                       string
	Port                         uint16
	GcTime                       time.Duration
	ResultChannel                chan<- DNSResult
	PacketHandlerCount           uint
	PacketChannelSize            uint
	TCPHandlerCount              uint
	TCPAssemblyChannelSize       uint
	TCPResultChannelSize         uint
	IPDefraggerChannelSize       uint
	IPDefraggerReturnChannelSize uint
	Done                         chan bool
}

type DNSCapturer struct {
	options    CaptureOptions
	processing chan gopacket.Packet
}

type DNSResult struct {
	Timestamp    time.Time
	DNS          mkdns.Msg
	IPVersion    uint8
	SrcIP        net.IP
	DstIP        net.IP
	Protocol     string
	PacketLength uint16
}

func initialize(devName, filter string) *pcap.Handle {
	// Open device
	handle, err := pcap.OpenLive(devName, 65536, true, 10*time.Millisecond)
	if err != nil {
		log.Fatal(err)
	}

	// Set Filter
	log.Printf("Using Device: %s\n", devName)
	log.Printf("Filter: %s\n", filter)
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	return handle
}

func handleInterrupt(done chan bool) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			log.Printf("SIGINT received")
			close(done)
			return
		}
	}()
}

func NewDNSCapturer(options CaptureOptions) DNSCapturer {
	var tcpChannels []chan tcpPacket

	tcpReturnChannel := make(chan tcpData, options.TCPResultChannelSize)
	processingChannel := make(chan gopacket.Packet, options.PacketChannelSize)
	ip4DefraggerChannel := make(chan layers.IPv4, options.IPDefraggerChannelSize)
	ip6DefraggerChannel := make(chan ipv6FragmentInfo, options.IPDefraggerChannelSize)
	ip4DefraggerReturn := make(chan layers.IPv4, options.IPDefraggerReturnChannelSize)
	ip6DefraggerReturn := make(chan layers.IPv6, options.IPDefraggerReturnChannelSize)

	for i := uint(0); i < options.TCPHandlerCount; i++ {
		tcpChannels = append(tcpChannels, make(chan tcpPacket, options.TCPAssemblyChannelSize))
		go tcpAssembler(tcpChannels[i], tcpReturnChannel, options.GcTime, options.Done)
	}

	go ipv4Defragger(ip4DefraggerChannel, ip4DefraggerReturn, options.GcTime, options.Done)
	go ipv6Defragger(ip6DefraggerChannel, ip6DefraggerReturn, options.GcTime, options.Done)

	encoder := packetEncoder{
		options.Port,
		processingChannel,
		ip4DefraggerChannel,
		ip6DefraggerChannel,
		ip4DefraggerReturn,
		ip6DefraggerReturn,
		tcpChannels,
		tcpReturnChannel,
		options.ResultChannel,
		options.Done,
	}

	for i := uint(0); i < options.PacketHandlerCount; i++ {
		go encoder.run()
	}
	return DNSCapturer{options, processingChannel}
}

func (capturer *DNSCapturer) Start() {
	options := capturer.options
	handle := initialize(options.DevName, options.Filter)
	defer handle.Close()

	// Setup SIGINT handling
	handleInterrupt(options.Done)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.DecodeOptions.Lazy = true
	packetSource.NoCopy = true
	log.Println("Waiting for packets")
	for {
		select {
		case packet := <-packetSource.Packets():
			if packet == nil {
				log.Println("PacketSource returned nil.")
				close(options.Done)
				return
			}
			select {
			case capturer.processing <- packet:
			default:
			}
		case <-options.Done:
			return
		}
	}
}
