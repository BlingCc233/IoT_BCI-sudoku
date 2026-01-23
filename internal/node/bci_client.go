package node

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"time"

	"github.com/BlingCc233/IoT_BCI-sudoku/internal/bci"
	"github.com/BlingCc233/IoT_BCI-sudoku/pkg/iotbci/frame"
	"github.com/BlingCc233/IoT_BCI-sudoku/pkg/iotbci/mux"
	"github.com/BlingCc233/IoT_BCI-sudoku/pkg/iotbci/uot"
)

func runStreamBCIEcho(ctx context.Context, conn net.Conn, sim BCISimConfig) error {
	g := simGenerator(sim)
	frames := sim.Frames
	if frames <= 0 {
		frames = 256
	}
	interval := time.Duration(sim.IntervalMillis) * time.Millisecond

	for i := 0; i < frames; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		payload := g.NextFrame()
		sum := sha256.Sum256(payload)
		if err := frame.Write(conn, payload); err != nil {
			return err
		}
		resp, err := frame.Read(conn, frame.MaxFrameSizeDefault)
		if err != nil {
			return err
		}
		if sha256.Sum256(resp) != sum {
			return fmt.Errorf("echo mismatch at frame %d", i)
		}
		if interval > 0 {
			time.Sleep(interval)
		}
	}
	return nil
}

func runMuxBCIEcho(ctx context.Context, conn net.Conn, sim BCISimConfig) error {
	g := simGenerator(sim)
	frames := sim.Frames
	if frames <= 0 {
		frames = 256
	}
	interval := time.Duration(sim.IntervalMillis) * time.Millisecond

	sess, err := mux.Dial(conn, mux.Config{})
	if err != nil {
		return err
	}
	defer sess.Close()

	st, err := sess.OpenStream([]byte("bci"))
	if err != nil {
		return err
	}
	defer st.Close()

	for i := 0; i < frames; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		payload := g.NextFrame()
		sum := sha256.Sum256(payload)
		if err := frame.Write(st, payload); err != nil {
			return err
		}
		resp, err := frame.Read(st, frame.MaxFrameSizeDefault)
		if err != nil {
			return err
		}
		if sha256.Sum256(resp) != sum {
			return fmt.Errorf("mux echo mismatch at frame %d", i)
		}
		if interval > 0 {
			time.Sleep(interval)
		}
	}
	return nil
}

func runUoTBCIEcho(ctx context.Context, conn net.Conn, sim BCISimConfig) error {
	g := simGenerator(sim)
	frames := sim.Frames
	if frames <= 0 {
		frames = 256
	}
	interval := time.Duration(sim.IntervalMillis) * time.Millisecond

	if err := uot.WritePreface(conn); err != nil {
		return err
	}
	pc := uot.NewPacketConn(conn)
	buf := make([]byte, 64*1024)
	dst := uot.Addr("bci")

	for i := 0; i < frames; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		payload := g.NextFrame()
		sum := sha256.Sum256(payload)
		if _, err := pc.WriteTo(payload, dst); err != nil {
			return err
		}
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			return err
		}
		resp := buf[:n]
		if sha256.Sum256(resp) != sum {
			return fmt.Errorf("uot echo mismatch at frame %d", i)
		}

		if interval > 0 {
			time.Sleep(interval)
		}
	}
	return nil
}

func simGenerator(sim BCISimConfig) *bci.Generator {
	g := &bci.Generator{
		Channels:          sim.Channels,
		SampleRateHz:      sim.SampleRateHz,
		SamplesPerChannel: sim.SamplesPerChannel,
		DeterministicSeed: sim.DeterministicSeed,
	}
	g.Init()
	return g
}
