package tun

import (
	"net"
)

type Config struct {
	Name string
	Net  []net.IPNet
	Peer string
	MTU  int
}
