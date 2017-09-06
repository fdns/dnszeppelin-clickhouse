package main

import (
	"flag"
	"fmt"
	"log"
	"runtime/pprof"
	"sync"
	"time"

	"encoding/binary"
	cdns "github.com/fdns/godnscapture"
	"github.com/kshvakov/clickhouse"
	data "github.com/kshvakov/clickhouse/lib/data"
	"net"
	"os"
	"runtime"
)

var devName = flag.String("devName", "", "Device used to capture")
var filter = flag.String("filter", "(ip or ip6)", "BPF filter applied to the packet stream. If port is selected, the packets will not be defragged.")
var port = flag.Uint("port", 53, "Port selected to filter packets")
var clickhouseAddress = flag.String("clickhouseAddress", "localhost:9000", "Address of the clickhouse database to save the results")
var batchSize = flag.Uint("batchSize", 100000, "Minimun capacity of the cache array used to send data to clickhouse. Set close to the queries per second received to prevent allocations")
var packetHandlerCount = flag.Uint("packetHandlers", 1, "Number of routines used to handle received packets")
var tcpHandlerCount = flag.Uint("tcpHandlers", 1, "Number of routines used to handle tcp assembly")
var packetChannelSize = flag.Uint("packetHandlerChannelSize", 100000, "Size of the packet handler channel")
var tcpAssemblyChannelSize = flag.Uint("tcpAssemblyChannelSize", 1000, "Size of the tcp assembler")
var tcpResultChannelSize = flag.Uint("tcpResultChannelSize", 1000, "Size of the tcp result channel")
var resultChannelSize = flag.Uint("resultChannelSize", 100000, "Size of the result processor channel size")
var defraggerChannelSize = flag.Uint("defraggerChannelSize", 500, "Size of the channel to send ipv4 packets to be defragged")
var defraggerChannelReturnSize = flag.Uint("defraggerChannelReturnSize", 500, "Size of the channel where the defragged ipv4 packet are returned")
var cpuprofile = flag.String("cpuprofile", "", "write cpu profile to file")
var memprofile = flag.String("memprofile", "", "write memory profile to `file`")


func min(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func output(resultChannel chan cdns.DnsResult, exiting chan bool, wg *sync.WaitGroup, clickhouseHost string, batchSize uint) {
	wg.Add(1)
	defer wg.Done()

	connect := connectClickhouseRetry(exiting, clickhouseHost)
	batch := make([]cdns.DnsResult, 0, batchSize)

	ticker := time.Tick(time.Second)
	for {
		select {
		case data := <-resultChannel:
			batch = append(batch, data)
		case <-ticker:
			if err := SendData(connect, batch); err != nil {
				log.Println(err)
				connect = connectClickhouseRetry(exiting, clickhouseHost)
			} else {
				batch = make([]cdns.DnsResult, 0, batchSize)
			}
		case <-exiting:
			return
		}
	}
}

func SendData(connect clickhouse.Clickhouse, batch []cdns.DnsResult) error {
	if len(batch) == 0 {
		return nil
	}

	// Return if the connection is null, we are exiting
	if connect == nil {
		return nil
	}
	log.Println("Sending ", len(batch))

	_, err := connect.Begin()
	if err != nil {
		return err
	}

	_, err = connect.Prepare("INSERT INTO DNS_LOG (DnsDate, timestamp, IPVersion, IPPrefix, Protocol, QR, OpCode, Class, Type, ResponceCode, Question, Size, Edns0Present, DoBit) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
	if err != nil {
		return err
	}

	block, err := connect.Block()
	if err != nil {
		return err
	}

	blocks := []*data.Block{block}

	count := len(blocks)
	var wg sync.WaitGroup
	wg.Add(len(blocks))
	for i := range blocks {
		b := blocks[i]
		start := i * (len(batch)) / count
		end := min((i+1)*(len(batch))/count, len(batch))

		go func() {
			defer wg.Done()
			b.Reserve()
			for k := start; k < end; k++ {
				for _, dnsQuery := range batch[k].Dns.Question {
					b.NumRows++
					b.WriteDate(0, batch[k].Timestamp)
					b.WriteDateTime(1, batch[k].Timestamp)
					b.WriteUInt8(2, batch[k].IPVersion)

					ip := batch[k].DstIP
					if batch[k].IPVersion == 4 {
						ip = ip.Mask(net.IPv4Mask(0xff, 0, 0, 0))
					}
					b.WriteUInt32(3, binary.BigEndian.Uint32(ip[:4]))
					b.WriteFixedString(4, []byte(batch[k].Protocol))
					QR := uint8(0)
					if batch[k].Dns.Response {
						QR = 1
					}

					b.WriteUInt8(5, QR)
					b.WriteUInt8(6, uint8(batch[k].Dns.Opcode))
					b.WriteUInt16(7, uint16(dnsQuery.Qclass))
					b.WriteUInt16(8, uint16(dnsQuery.Qtype))
					b.WriteUInt8(9, uint8(batch[k].Dns.Rcode))
					b.WriteString(10, string(dnsQuery.Name))
					b.WriteUInt16(11, batch[k].PacketLength)
					edns, doBit := uint8(0), uint8(0)
					if edns0 := batch[k].Dns.IsEdns0(); edns0 != nil {
						edns = 1
						if edns0.Do() {
							doBit = 1
						}
					}
					b.WriteUInt8(12, edns)
					b.WriteUInt8(13, doBit)
				}
			}
			if err := connect.WriteBlock(b); err != nil {
				return
			}
		}()
	}

	wg.Wait()
	if err := connect.Commit(); err != nil {
		return err
	}

	return nil
}

func checkFlags() {
	flag.Parse()
	if *port > 65535 {
		log.Fatal("-port must be between 1 and 65535")
	}

	if *devName == "" {
		log.Fatal("-devName is required")
	}
}

func main() {
	checkFlags()
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal("could not create CPU profile: ", err)
		}
		if err := pprof.StartCPUProfile(f); err != nil {
			log.Fatal("could not start CPU profile: ", err)
		}
		defer pprof.StopCPUProfile()
	}
	resultChannel := make(chan cdns.DnsResult, *resultChannelSize)

	// Setup output routine
	exiting := make(chan bool)
	var wg sync.WaitGroup
	go output(resultChannel, exiting, &wg, *clickhouseAddress, *batchSize)

	go func() {
		time.Sleep(120 * time.Second)
		if *memprofile != "" {
			fmt.Println("Writing mem")
			f, err := os.Create(*memprofile)
			if err != nil {
				log.Fatal("could not create memory profile: ", err)
			}
			runtime.GC() // get up-to-date statistics
			if err := pprof.WriteHeapProfile(f); err != nil {
				log.Fatal("could not write memory profile: ", err)
			}
			f.Close()
		}
	}()

	// Start listening
	capturer := cdns.NewDnsCapturer(cdns.CaptureOptions{
		*devName,
		*filter,
		uint16(*port),
		resultChannel,
		*packetHandlerCount,
		*packetChannelSize,
		*tcpHandlerCount,
		*tcpAssemblyChannelSize,
		*tcpResultChannelSize,
		*defraggerChannelSize,
		*defraggerChannelReturnSize,
		exiting,
	})
	capturer.Start()

	// Wait for the output to finish
	fmt.Println("Exiting")
	wg.Wait()
}
