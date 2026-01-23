package bench

import (
	"context"
	"testing"
	"time"

	"github.com/BlingCc233/IoT_BCI-sudoku/pkg/iotbci"
)

func TestRunIoTBCISudokuOnTCP_Smoke(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var gotTCP []uint16
	res, err := RunIoTBCISudokuOnTCP(ctx, RunConfig{Messages: 10, PayloadSize: 32}, true, 0, 2, "127.0.0.1:0", func(tcp, udp []uint16) {
		gotTCP = append([]uint16(nil), tcp...)
		_ = udp
	})
	if err != nil {
		t.Fatalf("RunIoTBCISudokuOnTCP: %v", err)
	}
	if res.Messages != 10 || res.PayloadSize != 32 {
		t.Fatalf("unexpected result: %+v", res)
	}
	if len(gotTCP) != 1 || gotTCP[0] == 0 {
		t.Fatalf("expected one TCP port from ready callback, got %v", gotTCP)
	}
}

func TestRunPureAEADOnTCP_Smoke(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var gotTCP []uint16
	res, err := RunPureAEADOnTCP(ctx, RunConfig{Messages: 10, PayloadSize: 32}, iotbci.AEADChaCha20Poly1305, "bench-psk-test", "127.0.0.1:0", func(tcp, udp []uint16) {
		gotTCP = append([]uint16(nil), tcp...)
		_ = udp
	})
	if err != nil {
		t.Fatalf("RunPureAEADOnTCP: %v", err)
	}
	if res.Messages != 10 || res.PayloadSize != 32 {
		t.Fatalf("unexpected result: %+v", res)
	}
	if len(gotTCP) != 1 || gotTCP[0] == 0 {
		t.Fatalf("expected one TCP port from ready callback, got %v", gotTCP)
	}
}
