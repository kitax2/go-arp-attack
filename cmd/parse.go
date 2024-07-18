package cmd

import (
	"context"
	"github.com/google/gopacket/pcap"
	"github.com/spf13/cobra"
	"go-arp-attack/spoofing"
	"golang.org/x/sync/errgroup"
	"log/slog"
	"net"
)

var (
	_root = cobra.Command{}

	Target        = _root.PersistentFlags().IPP("target", "t", nil, "example: 192.168.1.1")
	Gateway       = _root.PersistentFlags().IPP("gateway", "g", nil, "example: 192.168.1.1")
	InterfaceName = _root.PersistentFlags().StringP("interface", "i", "eth0", "interface name")
)

func ParseFlags(ctx context.Context) error {
	if err := pcap.LoadWinPCAP(); err != nil {
		return err
	}

	_root.RunE = func(cmd *cobra.Command, args []string) (err error) {
		var iface *net.Interface
		if iface, err = net.InterfaceByName(*InterfaceName); err != nil {
			var interfaces []net.Interface
			if interfaces, err = net.Interfaces(); err != nil {
				return err
			}

			for _, i := range interfaces {
				slog.Info("interface list", slog.String("name", i.Name), slog.String("mac", i.HardwareAddr.String()), slog.Int("mtu", i.MTU))
			}
			return err
		}

		var eg errgroup.Group
		eg.Go(func() error { return spoofing.SpoofedHost(ctx, iface, *Gateway, *Target) })
		return eg.Wait()
	}
	return _root.ExecuteContext(ctx)
}
