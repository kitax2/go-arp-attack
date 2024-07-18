package spoofing

import (
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log/slog"
	"net"
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

func SerializeAndSendData(handle *pcap.Handle, packet *gopacket.Packet) {
	var serializable = make([]gopacket.SerializableLayer, 0)
	for _, l := range (*packet).Layers() {
		if l == nil {
			continue
		}

		if serializableLayer, ok := l.(gopacket.SerializableLayer); ok && serializableLayer != nil {
			serializable = append(serializable, serializableLayer)
		}
	}

	var buffer = gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{}, serializable...); err == nil {
		if err = handle.WritePacketData(buffer.Bytes()); err != nil {
			return
		}
	}

	if ipv4, ok := (*packet).Layer(layers.LayerTypeIPv4).(*layers.IPv4); ok {
		if eth, ok := (*packet).Layer(layers.LayerTypeEthernet).(*layers.Ethernet); ok {
			slog.Info("forward data",
				slog.Group("src",
					slog.String("ip", fmt.Sprintf("%-16s", ipv4.SrcIP.String())),
					slog.String("mac", fmt.Sprintf("%-17s", eth.SrcMAC.String())),
				),
				slog.Group("dst",
					slog.String("ip", fmt.Sprintf("%-16s", ipv4.DstIP.String())),
					slog.String("mac", fmt.Sprintf("%-17s", eth.DstMAC.String())),
				),
			)
		}
	}
}
