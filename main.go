package main

import (
	"flag"
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
// Filter is not using "(port 53)", as it will filter out fragmented udp packets, instead, we filter by the ip protocol
// and check again in the application.
var filter = flag.String("filter", "((ip and (ip[9] == 6 or ip[9] == 17)) or (ip6 and (ip6[6] == 17 or ip6[6] == 6 or ip6[6] == 44)))", "BPF filter applied to the packet stream. If port is selected, the packets will not be defragged.")
var port = flag.Uint("port", 53, "Port selected to filter packets")
var gcTime = flag.Uint("gcTime", 60, "Time in seconds to garbage collect the tcp assembly and ipv4 defragmentation")
var clickhouseAddress = flag.String("clickhouseAddress", "localhost:9000", "Address of the clickhouse database to save the results")
var clickhouseDelay = flag.Uint("clickhouseDelay", 1, "Number of seconds to batch the packets")
var serverName = flag.String("serverName", "default", "Name of the server used to index the metrics.")
var batchSize = flag.Uint("batchSize", 100000, "Minimun capacity of the cache array used to send data to clickhouse. Set close to the queries per second received to prevent allocations")
var packetHandlerCount = flag.Uint("packetHandlers", 1, "Number of routines used to handle received packets")
var tcpHandlerCount = flag.Uint("tcpHandlers", 1, "Number of routines used to handle tcp assembly")
var packetChannelSize = flag.Uint("packetHandlerChannelSize", 100000, "Size of the packet handler channel")
var tcpAssemblyChannelSize = flag.Uint("tcpAssemblyChannelSize", 1000, "Size of the tcp assembler")
var tcpResultChannelSize = flag.Uint("tcpResultChannelSize", 1000, "Size of the tcp result channel")
var resultChannelSize = flag.Uint("resultChannelSize", 100000, "Size of the result processor channel size")
var defraggerChannelSize = flag.Uint("defraggerChannelSize", 500, "Size of the channel to send packets to be defragged")
var defraggerChannelReturnSize = flag.Uint("defraggerChannelReturnSize", 500, "Size of the channel where the defragged packets are returned")
var cpuprofile = flag.String("cpuprofile", "", "write cpu profile to file")
var memprofile = flag.String("memprofile", "", "write memory profile to `file`")
var loggerFilename = flag.Bool("loggerFilename", false, "Show the file name and number of the logged string")
var packetLimit = flag.Int("packetLimit", 0, "Limit of packets logged to clickhouse every iteration. Default 0 (disabled)")

func min(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func output(resultChannel chan cdns.DNSResult, exiting chan bool, wg *sync.WaitGroup, clickhouseHost string, batchSize, batchDelay uint, limit int, server string) {
	wg.Add(1)
	defer wg.Done()
	serverByte := []byte(server)

	connect := connectClickhouseRetry(exiting, clickhouseHost)
	batch := make([]cdns.DNSResult, 0, batchSize)

	ticker := time.Tick(time.Duration(batchDelay) * time.Second)
	for {
		select {
		case data := <-resultChannel:
			if limit == 0 || len(batch) < limit {
				batch = append(batch, data)
			}
		case <-ticker:
			if err := SendData(connect, batch, serverByte); err != nil {
				log.Println(err)
				connect = connectClickhouseRetry(exiting, clickhouseHost)
			} else {
				batch = make([]cdns.DNSResult, 0, batchSize)
			}
		case <-exiting:
			return
		}
	}
}

func SendData(connect clickhouse.Clickhouse, batch []cdns.DNSResult, server []byte) error {
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

	_, err = connect.Prepare("INSERT INTO DNS_LOG (DnsDate, timestamp, Server, IPVersion, IPPrefix, Protocol, QR, OpCode, Class, Type, ResponceCode, Question, Size, Edns0Present, DoBit) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
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
				for _, dnsQuery := range batch[k].DNS.Question {
					b.NumRows++
					b.WriteDate(0, batch[k].Timestamp)
					b.WriteDateTime(1, batch[k].Timestamp)
					b.WriteBytes(2, server)
					b.WriteUInt8(3, batch[k].IPVersion)

					ip := batch[k].DstIP
					if batch[k].IPVersion == 4 {
						ip = ip.Mask(net.IPv4Mask(0xff, 0, 0, 0))
					}
					b.WriteUInt32(4, binary.BigEndian.Uint32(ip[:4]))
					b.WriteFixedString(5, []byte(batch[k].Protocol))
					QR := uint8(0)
					if batch[k].DNS.Response {
						QR = 1
					}

					b.WriteUInt8(6, QR)
					b.WriteUInt8(7, uint8(batch[k].DNS.Opcode))
					b.WriteUInt16(8, uint16(dnsQuery.Qclass))
					b.WriteUInt16(9, uint16(dnsQuery.Qtype))
					b.WriteUInt8(10, uint8(batch[k].DNS.Rcode))
					b.WriteString(11, string(dnsQuery.Name))
					b.WriteUInt16(12, batch[k].PacketLength)
					edns, doBit := uint8(0), uint8(0)
					if edns0 := batch[k].DNS.IsEdns0(); edns0 != nil {
						edns = 1
						if edns0.Do() {
							doBit = 1
						}
					}
					b.WriteUInt8(13, edns)
					b.WriteUInt8(14, doBit)
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
	if *loggerFilename {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	} else {
		log.SetFlags(log.LstdFlags)
	}
	if *port > 65535 {
		log.Fatal("-port must be between 1 and 65535")
	}

	if *devName == "" {
		log.Fatal("-devName is required")
	}

	if *packetLimit < 0 {
		log.Fatal("-packetLimit must be equal or greather than 0")
	}
}

func main() {
	checkFlags()
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
	resultChannel := make(chan cdns.DNSResult, *resultChannelSize)

	// Setup output routine
	exiting := make(chan bool)
	var wg sync.WaitGroup
	go output(resultChannel, exiting, &wg, *clickhouseAddress, *batchSize, *clickhouseDelay, *packetLimit, *serverName)

	go func() {
		time.Sleep(120 * time.Second)
		if *memprofile != "" {
			log.Println("Writing memory profile")
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
	capturer := cdns.NewDNSCapturer(cdns.CaptureOptions{
		*devName,
		*filter,
		uint16(*port),
		time.Duration(*gcTime) * time.Second,
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
	log.Println("Exiting")
	wg.Wait()
}
