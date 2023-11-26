package tuntunnel

import (
	"net"
	"strings"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/core/metadata/util"
	tun_util "github.com/go-gost/gost/extension/utils/tun"
)

const (
	defaultMTU            = 1350
	defaultReadBufferSize = 4096
)

type metadata struct {
	config         *tun_util.Config
	readBufferSize int
}

func (l *tunListener) parseMetadata(md mdata.Metadata) (err error) {
	const (
		name   = "name"
		netKey = "net"
		peer   = "peer"
		mtu    = "mtu"
	)

	l.md.readBufferSize = mdutil.GetInt(md, "tun.rbuf", "rbuf", "readBufferSize")
	if l.md.readBufferSize <= 0 {
		l.md.readBufferSize = defaultReadBufferSize
	}

	config := &tun_util.Config{
		Name: mdutil.GetString(md, name),
		Peer: mdutil.GetString(md, peer),
		MTU:  mdutil.GetInt(md, mtu),
	}
	if config.MTU <= 0 {
		config.MTU = defaultMTU
	}

	for _, s := range strings.Split(mdutil.GetString(md, netKey), ",") {
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		ip, ipNet, err := net.ParseCIDR(s)
		if err != nil {
			continue
		}
		config.Net = append(config.Net, net.IPNet{
			IP:   ip,
			Mask: ipNet.Mask,
		})
	}

	l.md.config = config

	return
}
