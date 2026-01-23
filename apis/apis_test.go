package apis

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	"github.com/BlingCc233/IoT_BCI-sudoku/pkg/iotbci"
	"github.com/BlingCc233/IoT_BCI-sudoku/pkg/iotbci/mux"
)

func TestDialAndServerHandshake_Stream(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	masterPub, masterPriv, _ := ed25519.GenerateKey(rand.Reader)
	serverPub, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	clientPub, clientPriv, _ := ed25519.GenerateKey(rand.Reader)

	now := time.Now()
	serverCert, err := iotbci.IssueCert(masterPriv, "server-1", serverPub, now.Add(-time.Hour), now.Add(time.Hour), 1)
	if err != nil {
		t.Fatal(err)
	}
	clientCert, err := iotbci.IssueCert(masterPriv, "device-1", clientPub, now.Add(-time.Hour), now.Add(time.Hour), 2)
	if err != nil {
		t.Fatal(err)
	}

	sCfg := DefaultServerConfig()
	sCfg.Security.PSK = "test-psk"
	sCfg.Identity.MasterPublicKey = masterPub
	sCfg.Identity.LocalPrivateKey = serverPriv
	sCfg.Identity.LocalCert = serverCert

	cCfg := DefaultClientConfig()
	cCfg.Security.PSK = "test-psk"
	cCfg.Identity.MasterPublicKey = masterPub
	cCfg.Identity.LocalPrivateKey = clientPriv
	cCfg.Identity.LocalCert = clientCert

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	serverErr := make(chan error, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer raw.Close()

		sess, meta, err := ServerHandshake(ctx, raw, sCfg)
		if err != nil {
			serverErr <- err
			return
		}
		defer sess.Close()
		if meta == nil || meta.UserHash == "" {
			serverErr <- errMissingUserHash
			return
		}
		buf := make([]byte, 16)
		if _, err := io.ReadFull(sess, buf); err != nil {
			serverErr <- err
			return
		}
		if err := writeFull(sess, buf); err != nil {
			serverErr <- err
			return
		}
		serverErr <- nil
	}()

	conn, meta, err := Dial(ctx, ln.Addr().String(), cCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if meta == nil || meta.PeerSubject == "" {
		t.Fatalf("missing peer meta")
	}

	msg := []byte("0123456789abcdef")
	if err := writeFull(conn, msg); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatal(err)
	}
	if string(resp) != string(msg) {
		t.Fatalf("echo mismatch")
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestDialMuxAndAcceptMux(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	masterPub, masterPriv, _ := ed25519.GenerateKey(rand.Reader)
	serverPub, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	clientPub, clientPriv, _ := ed25519.GenerateKey(rand.Reader)

	now := time.Now()
	serverCert, err := iotbci.IssueCert(masterPriv, "server-1", serverPub, now.Add(-time.Hour), now.Add(time.Hour), 1)
	if err != nil {
		t.Fatal(err)
	}
	clientCert, err := iotbci.IssueCert(masterPriv, "device-1", clientPub, now.Add(-time.Hour), now.Add(time.Hour), 2)
	if err != nil {
		t.Fatal(err)
	}

	sCfg := DefaultServerConfig()
	sCfg.Security.PSK = "test-psk"
	sCfg.Identity.MasterPublicKey = masterPub
	sCfg.Identity.LocalPrivateKey = serverPriv
	sCfg.Identity.LocalCert = serverCert

	cCfg := DefaultClientConfig()
	cCfg.Security.PSK = "test-psk"
	cCfg.Identity.MasterPublicKey = masterPub
	cCfg.Identity.LocalPrivateKey = clientPriv
	cCfg.Identity.LocalCert = clientCert

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	serverErr := make(chan error, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer raw.Close()

		sess, _, err := AcceptMux(ctx, raw, sCfg, mux.Config{})
		if err != nil {
			serverErr <- err
			return
		}
		defer sess.Close()

		st, _, err := sess.AcceptStream(ctx)
		if err != nil {
			serverErr <- err
			return
		}
		defer st.Close()

		buf := make([]byte, 8)
		if _, err := io.ReadFull(st, buf); err != nil {
			serverErr <- err
			return
		}
		if err := writeFull(st, buf); err != nil {
			serverErr <- err
			return
		}
		serverErr <- nil
	}()

	mc, _, err := DialMux(ctx, ln.Addr().String(), cCfg, mux.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer mc.Close()

	st, err := mc.OpenStream([]byte("bci"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	msg := []byte("12345678")
	if err := writeFull(st, msg); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, len(msg))
	if _, err := io.ReadFull(st, resp); err != nil {
		t.Fatal(err)
	}
	if string(resp) != string(msg) {
		t.Fatalf("echo mismatch")
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestDialUoTAndAcceptUoT(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	masterPub, masterPriv, _ := ed25519.GenerateKey(rand.Reader)
	serverPub, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	clientPub, clientPriv, _ := ed25519.GenerateKey(rand.Reader)

	now := time.Now()
	serverCert, err := iotbci.IssueCert(masterPriv, "server-1", serverPub, now.Add(-time.Hour), now.Add(time.Hour), 1)
	if err != nil {
		t.Fatal(err)
	}
	clientCert, err := iotbci.IssueCert(masterPriv, "device-1", clientPub, now.Add(-time.Hour), now.Add(time.Hour), 2)
	if err != nil {
		t.Fatal(err)
	}

	sCfg := DefaultServerConfig()
	sCfg.Security.PSK = "test-psk"
	sCfg.Identity.MasterPublicKey = masterPub
	sCfg.Identity.LocalPrivateKey = serverPriv
	sCfg.Identity.LocalCert = serverCert

	cCfg := DefaultClientConfig()
	cCfg.Security.PSK = "test-psk"
	cCfg.Identity.MasterPublicKey = masterPub
	cCfg.Identity.LocalPrivateKey = clientPriv
	cCfg.Identity.LocalCert = clientCert

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	serverErr := make(chan error, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer raw.Close()

		pc, _, err := AcceptUoT(ctx, raw, sCfg)
		if err != nil {
			serverErr <- err
			return
		}
		defer pc.Close()

		buf := make([]byte, 1024)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			serverErr <- err
			return
		}
		if _, err := pc.WriteTo(buf[:n], addr); err != nil {
			serverErr <- err
			return
		}
		serverErr <- nil
	}()

	pc, _, err := DialUoT(ctx, ln.Addr().String(), cCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	msg := []byte("uot-echo")
	if _, err := pc.WriteTo(msg, iotbciAddr("bci")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1024)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != string(msg) {
		t.Fatalf("echo mismatch")
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

var errMissingUserHash = fmtErr("missing user hash")

type fmtErr string

func (e fmtErr) Error() string { return string(e) }

type iotbciAddr string

func (a iotbciAddr) Network() string { return "uot" }
func (a iotbciAddr) String() string  { return string(a) }

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
