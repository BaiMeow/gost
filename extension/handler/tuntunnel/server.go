package tuntunnel

import (
	"bytes"
	"context"
	"github.com/go-gost/core/common/bufpool"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/gost/extension/utils/tun"
	"github.com/songgao/water/waterutil"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"io"
	"net"
	"net/netip"
	"time"
)

func (h *tuntunnelHandler) handleServer(ctx context.Context, conn net.Conn, config *tun.Config, log logger.Logger) error {
	for {
		err := func() error {
			pc, err := net.ListenPacket(conn.LocalAddr().Network(), conn.LocalAddr().String())
			if err != nil {
				return err
			}
			defer pc.Close()

			return h.transportServer(ctx, conn, pc, config, log)
		}()
		if err == ErrTun {
			return err
		}

		log.Error(err)
		time.Sleep(time.Second)
	}
}

func (h *tuntunnelHandler) transportServer(ctx context.Context, tun io.ReadWriter, conn net.PacketConn, config *tun.Config, log logger.Logger) error {
	errc := make(chan error, 1)

	// tun -> net
	go func() {
		for {
			err := func() error {
				b := bufpool.Get(h.md.bufferSize)
				defer bufpool.Put(b)

				n, err := tun.Read(b)
				if err != nil {
					return ErrTun
				}
				if n == 0 {
					return nil
				}

				var src, dst net.IP
				if waterutil.IsIPv4(b[:n]) {
					header, err := ipv4.ParseHeader(b[:n])
					if err != nil {
						log.Warnf("parse ipv4 packet header: %v", err)
						return nil
					}
					src, dst = header.Src, header.Dst

					log.Tracef("%s >> %s %-4s %d/%-4d %-4x %d",
						src, dst, ipProtocol(waterutil.IPv4Protocol(b[:n])),
						header.Len, header.TotalLen, header.ID, header.Flags)
				} else if waterutil.IsIPv6(b[:n]) {
					header, err := ipv6.ParseHeader(b[:n])
					if err != nil {
						log.Warnf("parse ipv6 packet header: %v", err)
						return nil
					}
					src, dst = header.Src, header.Dst

					log.Tracef("%s >> %s %s %d %d",
						src, dst,
						ipProtocol(waterutil.IPProtocol(header.NextHeader)),
						header.PayloadLen, header.TrafficClass)
				} else {
					log.Warnf("unknown packet, discarded(%d)", n)
					return nil
				}

				if h.peerAddr == nil {
					log.Debugf("no route for %s -> %s, packet discarded", src, dst)
					return nil
				}

				log.Debugf("find route: %s -> %s", dst, h.peerAddr)

				if _, err := conn.WriteTo(b[:n], h.peerAddr); err != nil {
					return err
				}
				return nil
			}()

			if err != nil {
				errc <- err
				return
			}
		}
	}()

	// net -> tun
	go func() {
		for {
			err := func() error {
				b := bufpool.Get(h.md.bufferSize)
				defer bufpool.Put(b)

				n, addr, err := conn.ReadFrom(b)
				if err != nil {
					return err
				}
				if n == 0 {
					return nil
				}

				if n > keepAliveHeaderLength && bytes.Equal(b[:4], magicHeader) {
					if auther := h.options.Auther; auther != nil {
						ok := true
						key := bytes.TrimRight(b[4:20], "\x00")
						if _, ok = auther.Authenticate(ctx, config.Peer, string(key)); !ok {
							log.Debugf("keepalive from %v => %v, auth FAILED", addr, config.Peer)
							return nil
						}
					}

					log.Debugf("keepalive from %v => %v", addr, config.Peer)

					addrPort, err := netip.ParseAddrPort(addr.String())
					if err != nil {
						log.Warnf("keepalive from %v: %v", addr, err)
						return nil
					}
					var keepAliveData [keepAliveHeaderLength]byte
					copy(keepAliveData[:4], magicHeader) // magic header
					a16 := addrPort.Addr().As16()
					copy(keepAliveData[4:], a16[:])

					if _, err := conn.WriteTo(keepAliveData[:], addr); err != nil {
						log.Warnf("keepalive to %v: %v", addr, err)
						return nil
					}

					h.updateRoute(addr, log)
					return nil
				}

				var src, dst net.IP
				if waterutil.IsIPv4(b[:n]) {
					header, err := ipv4.ParseHeader(b[:n])
					if err != nil {
						log.Warnf("parse ipv4 packet header: %v", err)
						return nil
					}
					src, dst = header.Src, header.Dst

					log.Tracef("%s >> %s %-4s %d/%-4d %-4x %d",
						src, dst, ipProtocol(waterutil.IPv4Protocol(b[:n])),
						header.Len, header.TotalLen, header.ID, header.Flags)
				} else if waterutil.IsIPv6(b[:n]) {
					header, err := ipv6.ParseHeader(b[:n])
					if err != nil {
						log.Warnf("parse ipv6 packet header: %v", err)
						return nil
					}
					src, dst = header.Src, header.Dst

					log.Tracef("%s > %s %s %d %d",
						src, dst,
						ipProtocol(waterutil.IPProtocol(header.NextHeader)),
						header.PayloadLen, header.TrafficClass)
				} else {
					log.Warnf("unknown packet, discarded(%d): % x", n, b[:n])
					return nil
				}

				if _, err := tun.Write(b[:n]); err != nil {
					return ErrTun
				}
				return nil
			}()

			if err != nil {
				errc <- err
				return
			}
		}
	}()

	err := <-errc
	if err != nil && err == io.EOF {
		err = nil
	}
	return err
}

func (h *tuntunnelHandler) updateRoute(addr net.Addr, log logger.Logger) {
	if h.peerAddr != nil {
		old := h.peerAddr
		h.peerAddr = addr
		log.Debugf("update route: %s (old %s)",
			h.peerAddr, old.String())
	} else {
		h.peerAddr = addr
		log.Debugf("new route: %s -> %s", addr)
	}
}
