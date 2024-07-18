package send

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	MaxRetry = 3
)

func FindIPAndMacByInterface(iface *net.Interface) (_ net.IP, _ net.HardwareAddr, err error) {
	addrs, _ := iface.Addrs()
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !(ipNet.IP.IsLoopback() || ipNet.IP.IsLinkLocalUnicast() || ipNet.IP.IsMulticast()) {
			if v4 := ipNet.IP.To4(); v4 != nil {
				return v4, iface.HardwareAddr, nil
			}
		}
	}
	return nil, nil, errors.New("not found ip and MAC")
}

func OpenLive(iface *net.Interface) (_ *pcap.Handle, err error) {
	var ip net.IP
	if ip, _, err = FindIPAndMacByInterface(iface); err != nil {
		return nil, err
	}

	var devs []pcap.Interface
	if devs, err = pcap.FindAllDevs(); err != nil {
		return nil, err
	}

	for _, dev := range devs {
		for _, addr := range dev.Addresses {
			if addr.IP.IsLoopback() || addr.IP.IsLinkLocalUnicast() || addr.IP.IsMulticast() {
				continue
			}

			var v4 net.IP
			if v4 = addr.IP.To4(); v4 == nil {
				continue
			}

			if ip.Equal(v4) {
				return pcap.OpenLive(dev.Name, int32(iface.MTU), true, pcap.BlockForever)
			}
		}
	}
	return nil, errors.New("not found pcap handle")
}

func Request(ctx context.Context, iface *net.Interface, dstIP net.IP) (_ net.HardwareAddr, err error) {
	var srcIP net.IP
	var srcMac net.HardwareAddr
	if srcIP, srcMac, err = FindIPAndMacByInterface(iface); err != nil {
		return nil, err
	}

	var handle *pcap.Handle
	if handle, err = OpenLive(iface); err != nil {
		return nil, err
	}
	defer handle.Close()

	var packets = gopacket.NewPacketSource(handle, handle.LinkType()).Packets()
	for i := 0; i < MaxRetry; i++ {
		var data []byte
		if data, err = frame(layers.ARPRequest, srcIP, srcMac, dstIP, net.HardwareAddr{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}); err != nil {
			continue
		}

		if err = handle.WritePacketData(data); err != nil {
			continue
		}

		for timeout := time.NewTimer(time.Second); ; {
			select {
			case <-ctx.Done():
				err = ctx.Err()
				return // skip method
			case <-timeout.C:
				err = errors.New("request timeout")
				break
			case packet := <-packets:
				if packet.Layer(layers.LayerTypeARP) == nil {
					continue
				}

				layer := packet.Layer(layers.LayerTypeARP).(*layers.ARP)
				if !dstIP.Equal(layer.SourceProtAddress) {
					continue
				}
				return layer.SourceHwAddress, nil
			}
		}
	}

	if err != nil {
		return nil, err
	}

	return nil, errors.New("not found mac")
}

func ResponseWithSource(ctx context.Context, iface *net.Interface, srcIP net.IP, srcMac net.HardwareAddr, dstIP net.IP, dstMac net.HardwareAddr) (err error) {
	var handle *pcap.Handle
	if handle, err = OpenLive(iface); err != nil {
		return err
	}
	defer handle.Close()

	for i := 0; i < MaxRetry; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			var data []byte
			if data, err = frame(layers.ARPReply, srcIP, srcMac, dstIP, dstMac); err != nil {
				continue
			}

			if err = handle.WritePacketData(data); err != nil {
				continue
			}
		}
	}
	return
}

func frame(op uint16, srcIP net.IP, srcMac net.HardwareAddr, dstIP net.IP, dstMac net.HardwareAddr) (_ []byte, err error) {
	eth := layers.Ethernet{
		DstMAC:       dstMac,
		SrcMAC:       srcMac,
		EthernetType: layers.EthernetTypeARP,
	}

	packet := layers.ARP{
		ProtAddressSize:   4,
		HwAddressSize:     6,
		Operation:         op,
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		SourceHwAddress:   srcMac,
		SourceProtAddress: srcIP.To4(),
		DstHwAddress:      dstMac,
		DstProtAddress:    dstIP.To4(),
	}

	var f = gopacket.NewSerializeBuffer()
	if err = gopacket.SerializeLayers(f, gopacket.SerializeOptions{}, &eth, &packet); err != nil {
		return nil, err
	}
	return f.Bytes(), nil
}
