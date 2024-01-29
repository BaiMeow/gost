package smconn

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"github.com/tjfoc/gmsm/sm4"
	"io"
	"net"
)

type SMConn struct {
	net.Conn
	buf       *bytes.Buffer
	scrypt    cipher.AEAD
	nonce     []byte
	rcrypt    cipher.AEAD
	peerNonce []byte
}

func (s *SMConn) Read(b []byte) (n int, err error) {
	defer func() {
		if err != nil {
			s.Conn.Close()
		}
	}()

	if len(b) == 0 {
		return 0, nil
	}

	for s.buf.Len() < len(b) {
		var n uint16
		if err := binary.Read(s.Conn, binary.BigEndian, &n); err != nil {
			return 0, err
		}

		ciphertext := make([]byte, n)
		nn, err := io.ReadFull(s.Conn, ciphertext)
		if err != nil {
			return 0, err
		}
		if nn != int(n) {
			return 0, fmt.Errorf("read bytes not enough")
		}

		plaintext, err := s.rcrypt.Open(nil, s.peerNonce, ciphertext, nil)
		if err != nil {
			return 0, fmt.Errorf("decrypt failed: %v", err)
		}

		s.buf.Write(plaintext)
	}

	return io.ReadFull(s.buf, b)
}

func (s *SMConn) Write(b []byte) (n int, err error) {
	defer func() {
		if err != nil {
			s.Conn.Close()
		}
	}()

	if len(b) == 0 {
		return 0, nil
	}

	var buf []byte
	ciphertext := s.scrypt.Seal(nil, s.nonce, b, nil)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(ciphertext)))
	n, err = s.Conn.Write(append(buf, ciphertext...))
	if err != nil {
		return 0, fmt.Errorf("write conn failed: %v", err)
	}
	if n != len(ciphertext)+2 {
		return 0, fmt.Errorf("write bytes not enough")
	}

	return len(b), nil
}

func New(base net.Conn, key []byte) (*SMConn, error) {
	sm4cipher, err := sm4.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create sm4 cipher failed: %v", err)
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("create nonce failed: %v", err)
	}

	sendcrypt, err := cipher.NewGCM(sm4cipher)
	if err != nil {
		return nil, fmt.Errorf("create sm4 gcm failed: %v", err)
	}

	n, err := base.Write(nonce)
	if err != nil || n != 12 {
		return nil, fmt.Errorf("send nonce failed: %v", err)
	}

	peerNonce := make([]byte, 12)
	n, err = io.ReadFull(base, peerNonce)
	if err != nil || n != 12 {
		return nil, fmt.Errorf("reveive peer nonce failed: %v", err)
	}

	reccrypt, err := cipher.NewGCM(sm4cipher)
	if err != nil {
		return nil, fmt.Errorf("create sm4 gcm for receive failed: %v", err)
	}

	return &SMConn{
		buf:       &bytes.Buffer{},
		Conn:      base,
		scrypt:    sendcrypt,
		nonce:     nonce,
		rcrypt:    reccrypt,
		peerNonce: peerNonce,
	}, nil
}
