package node

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/BlingCc233/IoT_BCI-sudoku/pkg/iotbci"
	"github.com/BlingCc233/IoT_BCI-sudoku/pkg/iotbci/frame"
	"github.com/BlingCc233/IoT_BCI-sudoku/pkg/iotbci/mux"
	"github.com/BlingCc233/IoT_BCI-sudoku/pkg/iotbci/uot"
)

func Serve(ctx context.Context, cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("nil config")
	}
	if cfg.Listen == "" {
		return fmt.Errorf("listen is required")
	}
	opts, err := cfg.ToServerOptions()
	if err != nil {
		return err
	}

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	defer ln.Close()
	log.Printf("iotbci: server listening on %s (app=%s)", ln.Addr().String(), cfg.App)

	return serveLoop(ctx, cfg, opts, ln)
}

func serveStreamEcho(conn net.Conn) error {
	defer conn.Close()
	for {
		b, err := frame.Read(conn, frame.MaxFrameSizeDefault)
		if err != nil {
			return err
		}
		if err := frame.Write(conn, b); err != nil {
			return err
		}
	}
}

func serveMuxEcho(ctx context.Context, conn net.Conn) error {
	defer conn.Close()
	sess, err := mux.Accept(conn, mux.Config{})
	if err != nil {
		return err
	}
	defer sess.Close()

	for {
		st, _, err := sess.AcceptStream(ctx)
		if err != nil {
			return err
		}
		go func(c net.Conn) {
			defer c.Close()
			_, _ = io.Copy(c, c)
		}(st)
	}
}

func serveUoTEcho(conn net.Conn) error {
	defer conn.Close()
	if err := uot.ReadPreface(conn); err != nil {
		return err
	}

	pc := uot.NewPacketConn(conn)
	buf := make([]byte, 64*1024)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return err
		}
		_, err = pc.WriteTo(buf[:n], addr)
		if err != nil {
			return err
		}
	}
}

func DialAndRun(ctx context.Context, cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("nil config")
	}
	if cfg.Server == "" {
		return fmt.Errorf("server is required")
	}
	opts, err := cfg.ToClientOptions()
	if err != nil {
		return err
	}

	log.Printf("iotbci: client dialing %s (app=%s)", cfg.Server, cfg.App)
	raw, err := net.DialTimeout("tcp", cfg.Server, 5*time.Second)
	if err != nil {
		return err
	}
	defer raw.Close()

	sess, _, err := iotbci.ClientHandshake(ctx, raw, opts)
	if err != nil {
		log.Printf("iotbci: handshake failed: %v", err)
		return err
	}
	defer sess.Close()
	log.Printf("iotbci: handshake ok")

	switch cfg.App {
	case "stream", "":
		return runStreamBCIEcho(ctx, sess, cfg.BCI)
	case "mux":
		return runMuxBCIEcho(ctx, sess, cfg.BCI)
	case "uot":
		return runUoTBCIEcho(ctx, sess, cfg.BCI)
	default:
		return fmt.Errorf("unknown app: %s", cfg.App)
	}
}

func serveLoop(ctx context.Context, cfg *Config, opts *iotbci.ServerOptions, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go func(raw net.Conn) {
			defer func() { _ = raw.Close() }()

			log.Printf("iotbci: accept %s -> %s", raw.RemoteAddr().String(), raw.LocalAddr().String())
			sess, meta, err := iotbci.ServerHandshake(ctx, raw, opts)
			if err != nil {
				var se *iotbci.SuspiciousError
				if errors.As(err, &se) {
					log.Printf("iotbci: suspicious traffic from %s (%v), action=%s", raw.RemoteAddr().String(), se.Err, cfg.SuspiciousAction)
					HandleSuspicious(se.Conn, raw, cfg.FallbackAddr, cfg.SuspiciousAction)
					return
				}
				log.Printf("iotbci: handshake failed from %s: %v", raw.RemoteAddr().String(), err)
				return
			}
			_ = meta
			log.Printf("iotbci: handshake ok from %s", raw.RemoteAddr().String())

			switch cfg.App {
			case "stream", "":
				_ = serveStreamEcho(sess)
			case "mux":
				_ = serveMuxEcho(ctx, sess)
			case "uot":
				_ = serveUoTEcho(sess)
			default:
				_ = sess.Close()
			}
		}(conn)
	}
}
