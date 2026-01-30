package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/BlingCc233/IoT_BCI-sudoku/internal/bench"
	"github.com/BlingCc233/IoT_BCI-sudoku/pkg/iotbci"
)

type evidenceReport struct {
	GeneratedAt time.Time `json:"generated_at"`
	RepoRoot    string    `json:"repo_root"`

	CoreSourceBytes int64 `json:"core_source_bytes"`

	Scenarios []scenarioReport `json:"scenarios"`
}

type scenarioReport struct {
	Name string `json:"name"`

	TCPPorts []uint16 `json:"tcp_ports,omitempty"`
	UDPPorts []uint16 `json:"udp_ports,omitempty"`

	Metrics bench.ProtocolResult `json:"metrics"`

	Capture *captureReport `json:"capture,omitempty"`
}

type captureReport struct {
	Enabled bool   `json:"enabled"`
	Iface   string `json:"iface"`
	Filter  string `json:"filter"`

	PcapPath   string                 `json:"pcap_path"`
	ReportDir  string                 `json:"report_dir"`
	ReportJSON map[string]any         `json:"report_json,omitempty"`
	Error      string                 `json:"error,omitempty"`
	Meta       map[string]interface{} `json:"meta,omitempty"`
}

func main() {
	var (
		outDir   = flag.String("out_dir", "evidence_out", "output directory")
		msgs     = flag.Int("messages", 200, "messages (round trips)")
		size     = flag.Int("size", 256, "payload size (bytes)")
		timeout  = flag.Duration("timeout", 30*time.Second, "overall timeout")
		repoRoot = flag.String("repo_root", "", "repo root (default: current dir)")

		captureIface   = flag.String("capture_iface", "", "optional: enable pcap capture on interface (e.g. lo0/en0/eth0)")
		captureBinPath = flag.String("capture_bin", "", "optional: path to pcap-enabled iotbci-capture binary (default: auto-build with -tags pcap)")
		reportBinPath  = flag.String("report_bin", "", "optional: path to iotbci-report binary (default: auto-build)")
	)
	flag.Parse()

	root := *repoRoot
	if root == "" {
		wd, err := os.Getwd()
		if err != nil {
			fatal(err)
		}
		root = wd
	}
	root, _ = filepath.Abs(root)

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fatal(err)
	}

	coreBytes, err := bench.CoreSourceBytes(root)
	if err != nil {
		fatal(err)
	}

	rep := evidenceReport{
		GeneratedAt:     time.Now(),
		RepoRoot:        root,
		CoreSourceBytes: coreBytes,
	}

	captureEnabled := strings.TrimSpace(*captureIface) != ""
	var (
		captureBin string
		reportBin  string
	)
	if captureEnabled {
		captureBin = strings.TrimSpace(*captureBinPath)
		reportBin = strings.TrimSpace(*reportBinPath)

		toolsDir := filepath.Join(*outDir, ".tools")
		if err := os.MkdirAll(toolsDir, 0o755); err != nil {
			fatal(err)
		}

		if reportBin == "" {
			reportBin = filepath.Join(toolsDir, toolName("iotbci-report"))
			if err := buildTool(ctx, root, reportBin, "", "./cmd/iotbci-report"); err != nil {
				fatal(err)
			}
		}
		if captureBin == "" {
			captureBin = filepath.Join(toolsDir, toolName("iotbci-capture"))
			if err := buildTool(ctx, root, captureBin, "pcap", "./cmd/iotbci-capture"); err != nil {
				// libpcap missing or build failed -> proceed without capture.
				captureEnabled = false
			}
		}
	}

	cfg := bench.RunConfig{Messages: *msgs, PayloadSize: *size}

	scenarios := []struct {
		Name string
		Run  func(context.Context, bench.ReadyFunc) (bench.ProtocolResult, error)
	}{
		{
			Name: "iotbci-sudoku-pure-tcp",
			Run: func(ctx context.Context, ready bench.ReadyFunc) (bench.ProtocolResult, error) {
				return bench.RunIoTBCISudokuOnTCP(ctx, cfg, true, 2, 7, "127.0.0.1:0", ready)
			},
		},
		{
			Name: "iotbci-sudoku-packed-tcp",
			Run: func(ctx context.Context, ready bench.ReadyFunc) (bench.ProtocolResult, error) {
				return bench.RunIoTBCISudokuOnTCP(ctx, cfg, false, 2, 7, "127.0.0.1:0", ready)
			},
		},
		{
			Name: "pure-aead-tcp",
			Run: func(ctx context.Context, ready bench.ReadyFunc) (bench.ProtocolResult, error) {
				return bench.RunPureAEADOnTCP(ctx, cfg, iotbci.AEADChaCha20Poly1305, "bench-psk-pure-aead", "127.0.0.1:0", ready)
			},
		},
		{
			Name: "dtls-ecdhe-ecdsa-aes128gcm",
			Run: func(ctx context.Context, ready bench.ReadyFunc) (bench.ProtocolResult, error) {
				return bench.RunDTLSCertECDHEOnUDP(ctx, cfg, "127.0.0.1:0", ready)
			},
		},
		{
			Name: "coap-udp",
			Run: func(ctx context.Context, ready bench.ReadyFunc) (bench.ProtocolResult, error) {
				return bench.RunCoAPOnUDP(ctx, cfg, "127.0.0.1:0", ready)
			},
		},
		{
			Name: "mqtt-3.1.1-qos0-tls",
			Run: func(ctx context.Context, ready bench.ReadyFunc) (bench.ProtocolResult, error) {
				return bench.RunMQTTOnTLS(ctx, cfg, "127.0.0.1:0", ready)
			},
		},
	}

	for _, sc := range scenarios {
		scDir := filepath.Join(*outDir, sc.Name)
		if err := os.MkdirAll(scDir, 0o755); err != nil {
			fatal(err)
		}

		var (
			tcpPorts []uint16
			udpPorts []uint16

			capProc *exec.Cmd
			cap     *captureReport
		)
		ready := func(tcp, udp []uint16) {
			tcpPorts = append([]uint16(nil), tcp...)
			udpPorts = append([]uint16(nil), udp...)
			if !captureEnabled {
				return
			}
			filter := bpfFilter(tcpPorts, udpPorts)
			pcapPath := filepath.Join(scDir, "capture.pcap")
			cap = &captureReport{
				Enabled: true,
				Iface:   *captureIface,
				Filter:  filter,
				PcapPath: func() string {
					if rel, err := filepath.Rel(*outDir, pcapPath); err == nil {
						return rel
					}
					return pcapPath
				}(),
				ReportDir: filepath.Join(sc.Name, "pcap_report"),
			}

			capProc = exec.CommandContext(ctx, captureBin,
				"-iface", *captureIface,
				"-out", pcapPath,
				"-filter", filter,
			)
			capProc.Stdout = os.Stdout
			capProc.Stderr = os.Stderr
			if err := capProc.Start(); err != nil {
				cap.Error = err.Error()
				capProc = nil
				return
			}
			time.Sleep(150 * time.Millisecond)
		}

		res, err := sc.Run(ctx, ready)

		if capProc != nil && capProc.Process != nil {
			_ = capProc.Process.Signal(os.Interrupt)
			done := make(chan error, 1)
			go func() { done <- capProc.Wait() }()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				_ = capProc.Process.Kill()
				<-done
			}
		}
		if cap != nil && cap.Enabled && cap.Error == "" {
			pcapPath := filepath.Join(scDir, "capture.pcap")
			reportDir := filepath.Join(scDir, "pcap_report")
			_ = os.MkdirAll(reportDir, 0o755)
			args := []string{
				"-in", pcapPath,
				"-out_dir", reportDir,
			}
			if len(tcpPorts) > 0 {
				args = append(args, "-tcp_ports", joinPorts(tcpPorts))
			}
			if len(udpPorts) > 0 {
				args = append(args, "-udp_ports", joinPorts(udpPorts))
			}
			cmd := exec.CommandContext(ctx, reportBin, args...)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				cap.Error = fmt.Sprintf("report: %v", err)
			} else {
				b, err := os.ReadFile(filepath.Join(reportDir, "report.json"))
				if err == nil {
					var m map[string]any
					if json.Unmarshal(b, &m) == nil {
						cap.ReportJSON = m
					}
				}
			}
		}

		sr := scenarioReport{
			Name:     sc.Name,
			TCPPorts: tcpPorts,
			UDPPorts: udpPorts,
			Metrics:  res,
			Capture:  cap,
		}
		if err != nil {
			// Store the error in capture.error if capture is enabled; otherwise fail fast.
			if sr.Capture != nil {
				sr.Capture.Error = err.Error()
			} else {
				fatal(err)
			}
		}

		rep.Scenarios = append(rep.Scenarios, sr)

		out, _ := json.MarshalIndent(sr, "", "  ")
		_ = os.WriteFile(filepath.Join(scDir, "metrics.json"), append(out, '\n'), 0o644)
	}

	out, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		fatal(err)
	}
	if err := os.WriteFile(filepath.Join(*outDir, "evidence.json"), append(out, '\n'), 0o644); err != nil {
		fatal(err)
	}
}

func toolName(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}

func buildTool(ctx context.Context, repoRoot, outPath, tags, pkg string) error {
	args := []string{"build", "-o", outPath}
	if strings.TrimSpace(tags) != "" {
		args = append(args, "-tags", tags)
	}
	args = append(args, pkg)
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = repoRoot
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func joinPorts(p []uint16) string {
	out := make([]string, 0, len(p))
	for _, x := range p {
		out = append(out, strconv.Itoa(int(x)))
	}
	return strings.Join(out, ",")
}

func bpfFilter(tcpPorts, udpPorts []uint16) string {
	var parts []string
	for _, p := range tcpPorts {
		parts = append(parts, fmt.Sprintf("tcp port %d", p))
	}
	for _, p := range udpPorts {
		parts = append(parts, fmt.Sprintf("udp port %d", p))
	}
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	default:
		return "(" + strings.Join(parts, " or ") + ")"
	}
}

func fatal(err error) {
	_, _ = fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}
