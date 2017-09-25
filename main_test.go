package main

import (
	"database/sql"
	cdns "github.com/fdns/godnscapture"
	mkdns "github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"net"
	"sync"
	"testing"
	"time"
)

func TestSendData(t *testing.T) {
	resultChannel := make(chan cdns.DNSResult, 1)
	done := make(chan bool)
	var wg sync.WaitGroup
	go output(resultChannel, done, &wg, "localhost:9000", 10, 1, 10, "default")
	defer close(done)

	res := cdns.DNSResult{
		Timestamp:    time.Now(),
		IPVersion:    4,
		Protocol:     "udp",
		SrcIP:        net.IPv4(127, 0, 0, 1),
		DstIP:        net.IPv4(10, 0, 0, 1),
		PacketLength: 128,
	}
	res.DNS.SetQuestion("example.com.", mkdns.TypeA)
	resultChannel <- res

	// Wait for the insert
	time.Sleep(10 * time.Second)

	// Check the data was inserted
	connect, err := sql.Open("clickhouse", "tcp://127.0.0.1:9000?debug=false")
	if err != nil {
		t.Fatal(err)
	}
	rows, err := connect.Query("SELECT Server, IPVersion FROM DNS_LOG LIMIT 1")
	if err != nil {
		t.Fatal(err)
	}

	for rows.Next() {
		var (
			Server    string
			IPVersion uint8
		)
		if err := rows.Scan(&Server, &IPVersion); err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, "default", Server)
		assert.Equal(t, res.IPVersion, IPVersion)
	}
}
