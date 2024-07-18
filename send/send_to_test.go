package send_test

import (
	"context"
	"go-arp-attack/send"
	"net"
	"sync"
	"testing"
	"time"
)

const (
	InterfaceName = "WLAN"
	DeviceName    = "\\Device\\NPF_{8D493C9B-BA4B-43F6-BF04-85532C9CBAEE}"
)

func TestRequest(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	var err error
	var iface *net.Interface
	if iface, err = net.InterfaceByName("WLAN"); err != nil {
		return
	}

	var wg sync.WaitGroup
	for i := 0; i < 255; i++ {
		wg.Add(1)
		go func(dstIP net.IP) {
			defer wg.Done()

			var mac net.HardwareAddr
			if mac, err = send.Request(ctx, iface, dstIP); err != nil {
				t.Logf("%-20s %-20s %-20s", dstIP.To4().String(), "N/A", err.Error())
			} else {
				t.Logf("%-20s %-20s %-20s", dstIP.To4().String(), mac.String(), "N/A")
			}
		}(net.IPv4(192, 168, 2, byte(i)))
	}
	wg.Wait()
}
