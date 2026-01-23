//go:build stress

package mux

import (
	"context"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestStress_Mux_ManyStreams(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cRaw, sRaw := net.Pipe()
	defer cRaw.Close()
	defer sRaw.Close()

	cfg := Config{
		MaxFrameSize:            256 * 1024,
		MaxDataPayload:          8 * 1024,
		MaxStreams:              4096,
		MaxQueuedBytesPerStream: 256 * 1024,
		MaxQueuedBytesTotal:     8 * 1024 * 1024,
	}

	serverErr := make(chan error, 1)
	go func() {
		sess, err := Accept(sRaw, cfg)
		if err != nil {
			serverErr <- err
			return
		}
		defer sess.Close()

		for {
			st, _, err := sess.AcceptStream(ctx)
			if err != nil {
				if ctx.Err() != nil {
					serverErr <- nil
				} else {
					serverErr <- err
				}
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(st)
		}
	}()

	sess, err := Dial(cRaw, cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer sess.Close()

	streams := stressEnvInt("IOTBCI_STRESS_STREAMS", 256)
	payloadSize := stressEnvInt("IOTBCI_STRESS_STREAM_PAYLOAD", 16*1024)

	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte(i)
	}

	var wg sync.WaitGroup
	errCh := make(chan error, streams)

	for i := 0; i < streams; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st, err := sess.OpenStream(nil)
			if err != nil {
				errCh <- err
				return
			}
			defer st.Close()

			if _, err := st.Write(payload); err != nil {
				errCh <- err
				return
			}
			buf := make([]byte, len(payload))
			if _, err := io.ReadFull(st, buf); err != nil {
				errCh <- err
				return
			}
			errCh <- nil
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			t.Fatalf("mux stream failed: %v", err)
		}
	}

	cancel()
	if err := <-serverErr; err != nil {
		t.Fatalf("server: %v", err)
	}
}

func stressEnvInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}
