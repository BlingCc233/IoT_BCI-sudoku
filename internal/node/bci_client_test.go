package node

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/BlingCc233/IoT_BCI-sudoku/pkg/iotbci/frame"
	"github.com/BlingCc233/IoT_BCI-sudoku/pkg/iotbci/mux"
	"github.com/BlingCc233/IoT_BCI-sudoku/pkg/iotbci/uot"
)

func TestRunStreamBCIEcho(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sRaw, cRaw := net.Pipe()
	defer sRaw.Close()
	defer cRaw.Close()

	serverDone := make(chan error, 1)
	go func() {
		defer close(serverDone)
		for {
			b, err := frame.Read(sRaw, frame.MaxFrameSizeDefault)
			if err != nil {
				serverDone <- err
				return
			}
			if err := frame.Write(sRaw, b); err != nil {
				serverDone <- err
				return
			}
		}
	}()

	err := runStreamBCIEcho(ctx, cRaw, BCISimConfig{Frames: 10, DeterministicSeed: 1})
	if err != nil {
		t.Fatal(err)
	}
	_ = cRaw.Close()
}

func TestRunMuxBCIEcho(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sRaw, cRaw := net.Pipe()
	defer sRaw.Close()
	defer cRaw.Close()

	serverDone := make(chan error, 1)
	go func() {
		defer close(serverDone)
		sess, err := mux.Accept(sRaw, mux.Config{})
		if err != nil {
			serverDone <- err
			return
		}
		defer sess.Close()

		st, _, err := sess.AcceptStream(ctx)
		if err != nil {
			serverDone <- err
			return
		}
		defer st.Close()

		for {
			b, err := frame.Read(st, frame.MaxFrameSizeDefault)
			if err != nil {
				if err == io.EOF {
					serverDone <- nil
				} else {
					serverDone <- err
				}
				return
			}
			if err := frame.Write(st, b); err != nil {
				serverDone <- err
				return
			}
		}
	}()

	err := runMuxBCIEcho(ctx, cRaw, BCISimConfig{Frames: 10, DeterministicSeed: 1})
	if err != nil {
		t.Fatal(err)
	}
	_ = cRaw.Close()
}

func TestRunUoTBCIEcho(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sRaw, cRaw := net.Pipe()
	defer sRaw.Close()
	defer cRaw.Close()

	serverDone := make(chan error, 1)
	go func() {
		defer close(serverDone)
		if err := uot.ReadPreface(sRaw); err != nil {
			serverDone <- err
			return
		}
		pc := uot.NewPacketConn(sRaw)
		buf := make([]byte, 64*1024)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				if err == io.EOF {
					serverDone <- nil
				} else {
					serverDone <- err
				}
				return
			}
			if _, err := pc.WriteTo(buf[:n], addr); err != nil {
				serverDone <- err
				return
			}
		}
	}()

	err := runUoTBCIEcho(ctx, cRaw, BCISimConfig{Frames: 10, DeterministicSeed: 1})
	if err != nil {
		t.Fatal(err)
	}
	_ = cRaw.Close()
}
