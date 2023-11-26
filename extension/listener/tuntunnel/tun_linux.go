package tuntunnel

import (
	"io"
	"net"

	"github.com/vishvananda/netlink"
)

func (l *tunListener) createTun() (dev io.ReadWriteCloser, name string, ip net.IP, err error) {
	dev, name, err = l.createTunDevice()
	if err != nil {
		return
	}

	link, err := netlink.LinkByName(name)
	if err != nil {
		return
	}

	var peerIP *net.IPNet
	_, peerIP, err = net.ParseCIDR(l.md.config.Peer)
	if err != nil {
		return
	}

	for _, net := range l.md.config.Net {
		if err = netlink.AddrAdd(link, &netlink.Addr{
			IPNet: &net,
			Peer:  peerIP,
		}); err != nil {
			l.logger.Error(err)
			continue
		}
	}

	if len(l.md.config.Net) > 0 {
		ip = l.md.config.Net[0].IP
	}

	if err = netlink.LinkSetUp(link); err != nil {
		return
	}

	return
}
