package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BlingCc233/IoT_BCI-sudoku/internal/bench"
)

type outputReport struct {
	GeneratedAt time.Time            `json:"generated_at"`
	Role        string               `json:"role"`
	Proto       string               `json:"proto"`
	ListenAddr  string               `json:"listen_addr,omitempty"`
	ServerAddr  string               `json:"server_addr,omitempty"`
	Result      bench.ProtocolResult `json:"result"`
	Error       string               `json:"error,omitempty"`
}

type commonOpts struct {
	PSK        string
	PaddingMin int
	PaddingMax int
}

func main() {
	var (
		mode       = flag.String("mode", "client", "run mode: server|client")
		proto      = flag.String("proto", "iotbci-sudoku-pure-tcp", "protocol: iotbci-sudoku-pure-tcp|iotbci-sudoku-packed-tcp|pure-aead-tcp|dtls-psk-aes128gcm|coap-udp|mqtt-3.1.1-qos0-tls")
		listenAddr = flag.String("listen", "0.0.0.0:19001", "server listen addr")
		serverAddr = flag.String("server", "", "client server addr host:port")
		messages   = flag.Int("messages", 1000, "round-trip messages")
		size       = flag.Int("size", 256, "payload size bytes")
		timeout    = flag.Duration("timeout", 120*time.Second, "overall timeout")
		psk        = flag.String("psk", "netbench-psk-v1", "shared psk used by dtls/aead/sudoku")
		padMin     = flag.Int("sudoku_padding_min", 0, "sudoku padding min percentage")
		padMax     = flag.Int("sudoku_padding_max", 0, "sudoku padding max percentage")
		outPath    = flag.String("out", "", "optional output json path")
	)
	flag.Parse()

	cfg := bench.RunConfig{Messages: *messages, PayloadSize: *size}
	opts := commonOpts{
		PSK:        *psk,
		PaddingMin: *padMin,
		PaddingMax: *padMax,
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	rep := outputReport{
		GeneratedAt: time.Now(),
		Role:        strings.ToLower(strings.TrimSpace(*mode)),
		Proto:       strings.TrimSpace(*proto),
		ListenAddr:  strings.TrimSpace(*listenAddr),
		ServerAddr:  strings.TrimSpace(*serverAddr),
	}

	var (
		res    bench.ProtocolResult
		actual string
		err    error
	)

	switch rep.Role {
	case "server":
		res, actual, err = runServer(ctx, rep.Proto, rep.ListenAddr, cfg, opts)
		rep.ListenAddr = actual
		if err == nil {
			fmt.Fprintf(os.Stderr, "READY %s %s\n", rep.Proto, actual)
		}
	case "client":
		if rep.ServerAddr == "" {
			fatalf("-server is required in client mode")
		}
		res, err = runClient(ctx, rep.Proto, rep.ServerAddr, cfg, opts)
	default:
		fatalf("invalid -mode %q", rep.Role)
	}

	if err != nil {
		rep.Error = err.Error()
	}
	rep.Result = res

	out, mErr := json.MarshalIndent(rep, "", "  ")
	if mErr != nil {
		fatalf("marshal report: %v", mErr)
	}
	out = append(out, '\n')

	if strings.TrimSpace(*outPath) != "" {
		if err := os.MkdirAll(filepath.Dir(*outPath), 0o755); err != nil {
			fatalf("mkdir out dir: %v", err)
		}
		if err := os.WriteFile(*outPath, out, 0o644); err != nil {
			fatalf("write report: %v", err)
		}
	} else {
		_, _ = os.Stdout.Write(out)
	}

	if err != nil {
		os.Exit(1)
	}
}

func runServer(ctx context.Context, proto, listen string, cfg bench.RunConfig, opts commonOpts) (bench.ProtocolResult, string, error) {
	switch strings.TrimSpace(proto) {
	case "iotbci-sudoku-pure-tcp":
		return runSudokuServer(ctx, listen, cfg, opts, true)
	case "iotbci-sudoku-packed-tcp":
		return runSudokuServer(ctx, listen, cfg, opts, false)
	case "pure-aead-tcp":
		return runPureAEADServer(ctx, listen, cfg, opts)
	case "dtls-psk-aes128gcm":
		return runDTLSServer(ctx, listen, cfg, opts)
	case "coap-udp":
		return runCoAPServer(ctx, listen, cfg)
	case "mqtt-3.1.1-qos0-tls":
		return runMQTTTLSServer(ctx, listen, cfg)
	default:
		return bench.ProtocolResult{}, "", fmt.Errorf("unsupported proto: %s", proto)
	}
}

func runClient(ctx context.Context, proto, server string, cfg bench.RunConfig, opts commonOpts) (bench.ProtocolResult, error) {
	switch strings.TrimSpace(proto) {
	case "iotbci-sudoku-pure-tcp":
		return runSudokuClient(ctx, server, cfg, opts, true)
	case "iotbci-sudoku-packed-tcp":
		return runSudokuClient(ctx, server, cfg, opts, false)
	case "pure-aead-tcp":
		return runPureAEADClient(ctx, server, cfg, opts)
	case "dtls-psk-aes128gcm":
		return runDTLSClient(ctx, server, cfg, opts)
	case "coap-udp":
		return runCoAPClient(ctx, server, cfg)
	case "mqtt-3.1.1-qos0-tls":
		return runMQTTTLSClient(ctx, server, cfg)
	default:
		return bench.ProtocolResult{}, fmt.Errorf("unsupported proto: %s", proto)
	}
}

func fatalf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(2)
}
