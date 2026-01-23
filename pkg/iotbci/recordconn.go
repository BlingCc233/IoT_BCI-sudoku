package iotbci

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

var (
	ErrDecryptFailed = errors.New("iotbci: decryption failed")
)

type recordConn struct {
	net.Conn

	aeadTx cipher.AEAD
	aeadRx cipher.AEAD

	txSalt [4]byte
	rxSalt [4]byte

	txSeq uint64
	rxSeq uint64

	writeMu sync.Mutex
	readMu  sync.Mutex
	readBuf bytes.Buffer

	writeBuf    []byte
	rxCipherBuf []byte
	rxPlainBuf  []byte

	txNonceBuf [12]byte
	rxNonceBuf [12]byte
}

func NewRecordConn(base net.Conn, method AEADMethod, txKey []byte, rxKey []byte, txSalt [4]byte, rxSalt [4]byte) (net.Conn, error) {
	if base == nil {
		return nil, fmt.Errorf("nil conn")
	}
	if method == AEADNone {
		return base, nil
	}
	aeadTx, err := newAEAD(method, txKey)
	if err != nil {
		return nil, err
	}
	aeadRx, err := newAEAD(method, rxKey)
	if err != nil {
		return nil, err
	}
	return &recordConn{
		Conn:   base,
		aeadTx: aeadTx,
		aeadRx: aeadRx,
		txSalt: txSalt,
		rxSalt: rxSalt,
	}, nil
}

func newAEAD(method AEADMethod, key []byte) (cipher.AEAD, error) {
	switch method {
	case AEADAES128GCM:
		if len(key) < 16 {
			return nil, fmt.Errorf("aes-128-gcm key too short: %d", len(key))
		}
		block, err := aes.NewCipher(key[:16])
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	case AEADChaCha20Poly1305:
		if len(key) < chacha20poly1305.KeySize {
			return nil, fmt.Errorf("chacha20-poly1305 key too short: %d", len(key))
		}
		return chacha20poly1305.New(key[:chacha20poly1305.KeySize])
	default:
		return nil, fmt.Errorf("unsupported aead: %s", method)
	}
}

func (c *recordConn) CloseWrite() error {
	if c == nil || c.Conn == nil {
		return nil
	}
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (c *recordConn) CloseRead() error {
	if c == nil || c.Conn == nil {
		return nil
	}
	if cr, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return nil
}

func (c *recordConn) makeNonce(dst *[12]byte, salt [4]byte, seq uint64) []byte {
	copy(dst[:4], salt[:])
	binary.BigEndian.PutUint64(dst[4:], seq)
	return dst[:]
}

func (c *recordConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if c.aeadTx == nil {
		return c.Conn.Write(p)
	}

	overhead := c.aeadTx.Overhead()
	maxPlain := int(^uint16(0)) - overhead
	if maxPlain <= 0 {
		return 0, fmt.Errorf("invalid aead overhead")
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	total := 0
	var header [2]byte

	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxPlain {
			chunk = p[:maxPlain]
		}

		needCipherCap := len(chunk) + overhead
		if cap(c.writeBuf) < needCipherCap {
			c.writeBuf = make([]byte, 0, needCipherCap)
		}

		nonce := c.makeNonce(&c.txNonceBuf, c.txSalt, c.txSeq)
		ciphertext := c.aeadTx.Seal(c.writeBuf[:0], nonce, chunk, nil)
		c.txSeq++

		if len(ciphertext) > int(^uint16(0)) {
			return total, fmt.Errorf("ciphertext too large: %d", len(ciphertext))
		}
		binary.BigEndian.PutUint16(header[:], uint16(len(ciphertext)))
		if err := writeFull(c.Conn, header[:]); err != nil {
			return total, err
		}
		if err := writeFull(c.Conn, ciphertext); err != nil {
			return total, err
		}
		c.writeBuf = ciphertext[:0]

		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

func (c *recordConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if c.aeadRx == nil {
		return c.Conn.Read(p)
	}

	c.readMu.Lock()
	defer c.readMu.Unlock()

	if c.readBuf.Len() > 0 {
		return c.readBuf.Read(p)
	}

	var header [2]byte
	if _, err := io.ReadFull(c.Conn, header[:]); err != nil {
		return 0, err
	}
	n := int(binary.BigEndian.Uint16(header[:]))
	if n <= 0 || n > int(^uint16(0)) {
		return 0, fmt.Errorf("%w: invalid record length %d", ErrProtocolViolation, n)
	}

	if cap(c.rxCipherBuf) < n {
		c.rxCipherBuf = make([]byte, n)
	}
	ciphertext := c.rxCipherBuf[:n]
	if _, err := io.ReadFull(c.Conn, ciphertext); err != nil {
		return 0, err
	}

	nonce := c.makeNonce(&c.rxNonceBuf, c.rxSalt, c.rxSeq)
	if cap(c.rxPlainBuf) < n {
		c.rxPlainBuf = make([]byte, 0, n)
	}
	plaintext, err := c.aeadRx.Open(c.rxPlainBuf[:0], nonce, ciphertext, nil)
	if err != nil {
		return 0, ErrDecryptFailed
	}
	c.rxSeq++

	c.readBuf.Write(plaintext)
	return c.readBuf.Read(p)
}

func writeFull(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}

// DerivePSKHandshakeKeys deterministically derives directional handshake keys from PSK.
// This keeps handshake encryption independent from the forward-secure session keys.
func DerivePSKHandshakeKeys(psk string) (c2sKey [32]byte, s2cKey [32]byte, c2sSalt [4]byte, s2cSalt [4]byte) {
	h1 := sha256.Sum256(append([]byte("iotbci-hs-c2s:"), []byte(psk)...))
	h2 := sha256.Sum256(append([]byte("iotbci-hs-s2c:"), []byte(psk)...))
	c2sKey = h1
	s2cKey = h2
	s1 := sha256.Sum256(append([]byte("iotbci-hs-c2s-salt:"), []byte(psk)...))
	s2 := sha256.Sum256(append([]byte("iotbci-hs-s2c-salt:"), []byte(psk)...))
	copy(c2sSalt[:], s1[:4])
	copy(s2cSalt[:], s2[:4])
	return
}
