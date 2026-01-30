package bench

import (
	"context"
	"time"

	"github.com/BlingCc233/IoT_BCI-sudoku/pkg/iotbci"
)

func RunAll(ctx context.Context, repoRoot string, cfg RunConfig) (Report, error) {
	coreBytes, err := CoreSourceBytes(repoRoot)
	if err != nil {
		return Report{}, err
	}

	results := make([]ProtocolResult, 0, 8)

	r1, err := RunIoTBCISudoku(ctx, cfg, true, 2, 7)
	if err != nil {
		return Report{}, err
	}
	results = append(results, r1)

	r2, err := RunIoTBCISudoku(ctx, cfg, false, 2, 7)
	if err != nil {
		return Report{}, err
	}
	results = append(results, r2)

	r3, err := RunPureAEAD(ctx, cfg, iotbci.AEADChaCha20Poly1305, "bench-psk-pure-aead")
	if err != nil {
		return Report{}, err
	}
	results = append(results, r3)

	r4, err := RunDTLSCertECDHE(ctx, cfg)
	if err != nil {
		return Report{}, err
	}
	results = append(results, r4)

	r5, err := RunCoAP(ctx, cfg)
	if err != nil {
		return Report{}, err
	}
	results = append(results, r5)

	r6, err := RunMQTT(ctx, cfg)
	if err != nil {
		return Report{}, err
	}
	results = append(results, r6)

	return Report{
		GeneratedAt:     time.Now(),
		CoreSourceBytes: coreBytes,
		Results:         results,
	}, nil
}
