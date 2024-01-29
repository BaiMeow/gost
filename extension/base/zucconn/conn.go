package zucconn

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"github.com/emmansun/gmsm/zuc"
	"io"
	"net"
)

type ZUConn struct {
	net.Conn
	send *cipher.StreamWriter
	rec  *cipher.StreamReader
}

func (c *ZUConn) Read(b []byte) (n int, err error) {
	defer func() {
		if err != nil {
			c.Conn.Close()
		}
	}()

	if len(b) == 0 {
		return 0, nil
	}

	return c.rec.Read(b)
}

func (c *ZUConn) Write(b []byte) (n int, err error) {
	defer func() {
		if err != nil {
			c.Conn.Close()
		}
	}()

	if len(b) == 0 {
		return 0, nil
	}

	return c.send.Write(b)
}

func New(base net.Conn, key []byte) (*ZUConn, error) {
	iv := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("create iv failed: %v", err)
	}
	s, err := zuc.NewCipher(key, iv)
	if err != nil {
		return nil, fmt.Errorf("create zuc stream failed: %v", err)
	}

	n, err := base.Write(iv)
	if err != nil || n != 16 {
		return nil, fmt.Errorf("send iv failed: %v", err)
	}

	peeriv := make([]byte, 16)
	n, err = io.ReadFull(base, peeriv)
	if err != nil || n != 16 {
		return nil, fmt.Errorf("reveive peer iv failed: %v", err)
	}

	r, err := zuc.NewCipher(key, peeriv)
	if err != nil {
		return nil, fmt.Errorf("create zuc stream failed: %v", err)
	}

	return &ZUConn{
		Conn: base,
		send: &cipher.StreamWriter{S: s, W: base},
		rec:  &cipher.StreamReader{S: r, R: base},
	}, nil
}
