package dnszeppelin

import (
	mkdns "github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"
)

// helpers

func hasRootAccess() bool {
	cmd := exec.Command("id", "-u")
	output, err := cmd.Output()

	if err != nil {
		return false
	}

	// 0 = root, 501 = non-root user
	i, err := strconv.Atoi(string(output[:len(output)-1]))

	if err != nil {
		return false
	}

	if i == 0 {
		return true
	}
	return false
}

func createCapturer(size uint) (chan DNSResult, DNSCapturer) {
	resultChannel := make(chan DNSResult, 10)
	done := make(chan bool)
	capturer := NewDNSCapturer(CaptureOptions{
		"lo",
		"",
		"(ip or ip6)",
		53,
		2 * time.Second,
		resultChannel,
		1,
		size,
		1,
		1,
		10,
		10,
		10,
		done,
	})
	return resultChannel, capturer
}

func createDefaultCapturer() (chan DNSResult, DNSCapturer) {
	return createCapturer(10)
}

/* Tests */
func TestCreateCapture(t *testing.T) {
	rChannel, capturer := createDefaultCapturer()
	close(capturer.options.Done)
	close(rChannel)
}

func TestCaptureStart(t *testing.T) {
	t.Parallel()
	if !hasRootAccess() {
		t.Skip("No root access")
	}
	rChannel, capturer := createDefaultCapturer()
	go func() {
		capturer.Start()
	}()
	// Wait for the setup
	time.Sleep(time.Second)

	// Close the channels
	close(capturer.options.Done)
	close(rChannel)
}

func TestCloseOnSIGINT(t *testing.T) {
	if !hasRootAccess() {
		t.Skip("No root access")
	}
	rChannel, capturer := createDefaultCapturer()
	go func() {
		capturer.Start()
	}()
	// Wait for the setup
	time.Sleep(time.Second)
	// Send sigint
	proc, _ := os.FindProcess(os.Getpid())
	proc.Signal(os.Interrupt)

	// Check the done channel
	_, ok := <-capturer.options.Done
	assert.False(t, ok, "Channel done not closed on Interrupt")

	// Close the channels
	close(rChannel)
}

// Benchmark
func BenchmarkUDPParsing(b *testing.B) {
	rChannel, capturer := createCapturer(100000)
	defer close(capturer.options.Done)
	defer close(rChannel)

	data := new(mkdns.Msg)
	data.SetQuestion("example.com.", mkdns.TypeA)
	pack, _ := data.Pack()

	packet := generateUDPPacket(pack)
	go func() {
		// Consume all the processed data
		for {
			<-rChannel
		}
	}()
	for i := 0; i < b.N; i++ {
		capturer.processing <- packet
	}
}
