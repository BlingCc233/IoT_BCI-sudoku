package main

import (
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/BlingCc233/IoT_BCI-sudoku/internal/bench"
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

	PcapPath   string         `json:"pcap_path"`
	ReportDir  string         `json:"report_dir"`
	ReportJSON map[string]any `json:"report_json,omitempty"`
	Error      string         `json:"error,omitempty"`
}

type attackReport struct {
	GeneratedAt time.Time      `json:"generated_at"`
	Scenarios   []attackResult `json:"scenarios"`
}

type attackResult struct {
	Name        string   `json:"name"`
	Expected    string   `json:"expected"`
	Success     bool     `json:"success"`
	DurationMs  float64  `json:"duration_ms"`
	ServerError string   `json:"server_error,omitempty"`
	ClientError string   `json:"client_error,omitempty"`
	Notes       []string `json:"notes,omitempty"`
}

type viewModel struct {
	Title string
	Now   string

	Bench    *bench.Report
	Evidence *evidenceReport
	Attack   *attackReport

	BenchSummary    *summary
	EvidenceSummary *summary

	BenchInsights    []string
	EvidenceInsights []string
}

type summary struct {
	LowestOverheadName  string
	LowestOverheadRatio float64

	LowestRTTName string
	LowestRTTMs   float64

	LowestMemName string
	LowestMemMB   float64

	AvgDurationMs float64
	MaxSysMemMB   float64
}

//go:embed page.html
var pageHTML string

func main() {
	var (
		benchPath    = flag.String("bench", "", "optional: bench.json from cmd/iotbci-bench")
		evidencePath = flag.String("evidence", "", "optional: evidence_out/evidence.json from cmd/iotbci-evidence")
		attackPath   = flag.String("attack", "", "optional: attack_report.json from cmd/iotbci-attack")
		outDir       = flag.String("out_dir", "dashboard_out", "output directory")
		title        = flag.String("title", "IoT_BCI-sudoku Report", "HTML title")
	)
	flag.Parse()

	if strings.TrimSpace(*benchPath) == "" && strings.TrimSpace(*evidencePath) == "" && strings.TrimSpace(*attackPath) == "" {
		fatal(fmt.Errorf("at least one of -bench, -evidence, or -attack is required"))
	}

	var (
		br *bench.Report
		er *evidenceReport
		ar *attackReport
	)

	if strings.TrimSpace(*benchPath) != "" {
		b, err := os.ReadFile(*benchPath)
		if err != nil {
			fatal(err)
		}
		var rep bench.Report
		if err := json.Unmarshal(b, &rep); err != nil {
			fatal(err)
		}
		br = &rep
	}

	if strings.TrimSpace(*evidencePath) != "" {
		b, err := os.ReadFile(*evidencePath)
		if err != nil {
			fatal(err)
		}
		var rep evidenceReport
		if err := json.Unmarshal(b, &rep); err != nil {
			fatal(err)
		}
		er = &rep
	}

	if strings.TrimSpace(*attackPath) != "" {
		b, err := os.ReadFile(*attackPath)
		if err != nil {
			fatal(err)
		}
		var rep attackReport
		if err := json.Unmarshal(b, &rep); err != nil {
			fatal(err)
		}
		ar = &rep
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fatal(err)
	}

	vm := viewModel{
		Title:    *title,
		Now:      time.Now().Format(time.RFC3339),
		Bench:    br,
		Evidence: er,
		Attack:   ar,
	}
	if br != nil {
		vm.BenchSummary = summarizeBench(br.Results)
		vm.BenchInsights = sudokuInsights(br.Results)
	}
	if er != nil {
		results := make([]bench.ProtocolResult, 0, len(er.Scenarios))
		for _, sc := range er.Scenarios {
			results = append(results, sc.Metrics)
		}
		vm.EvidenceSummary = summarizeBench(results)
		vm.EvidenceInsights = sudokuInsights(results)
	}

	outPath := filepath.Join(*outDir, "index.html")
	if err := writeHTML(outPath, vm); err != nil {
		fatal(err)
	}
}

func summarizeBench(results []bench.ProtocolResult) *summary {
	if len(results) == 0 {
		return nil
	}
	s := &summary{
		LowestOverheadRatio: math.Inf(1),
		LowestRTTMs:         math.Inf(1),
		LowestMemMB:         math.Inf(1),
	}

	var sumDur float64
	var maxSys uint64
	for _, r := range results {
		sumDur += r.DurationMillis
		if r.OverheadRatio > 0 && r.OverheadRatio < s.LowestOverheadRatio {
			s.LowestOverheadRatio = r.OverheadRatio
			s.LowestOverheadName = r.Name
		}
		if r.AvgRTTMillis > 0 && r.AvgRTTMillis < s.LowestRTTMs {
			s.LowestRTTMs = r.AvgRTTMillis
			s.LowestRTTName = r.Name
		}
		memMB := float64(r.PeakHeapInuseBytes) / 1024.0 / 1024.0
		if memMB > 0 && memMB < s.LowestMemMB {
			s.LowestMemMB = memMB
			s.LowestMemName = r.Name
		}
		if r.PeakSysBytes > maxSys {
			maxSys = r.PeakSysBytes
		}
	}
	s.AvgDurationMs = sumDur / float64(len(results))
	s.MaxSysMemMB = float64(maxSys) / 1024.0 / 1024.0
	if !isFinite(s.LowestOverheadRatio) {
		s.LowestOverheadRatio = 0
	}
	if !isFinite(s.LowestRTTMs) {
		s.LowestRTTMs = 0
	}
	if !isFinite(s.LowestMemMB) {
		s.LowestMemMB = 0
	}
	return s
}

func isFinite(f float64) bool { return !math.IsInf(f, 0) && !math.IsNaN(f) }

func sudokuInsights(results []bench.ProtocolResult) []string {
	pure, okPure := findByContains(results, "iotbci-sudoku-pure")
	packed, okPacked := findByContains(results, "iotbci-sudoku-packed")
	if !okPure || !okPacked {
		return nil
	}

	out := make([]string, 0, 6)

	if pure.OverheadRatio > 0 && packed.OverheadRatio > 0 {
		deltaPct := (pure.OverheadRatio - packed.OverheadRatio) / pure.OverheadRatio * 100
		out = append(out, fmt.Sprintf("Packed vs Pure overhead: %.2fx → %.2fx (%.1f%%)", pure.OverheadRatio, packed.OverheadRatio, deltaPct))
	}
	if pure.AvgRTTMillis > 0 && packed.AvgRTTMillis > 0 {
		deltaPct := (pure.AvgRTTMillis - packed.AvgRTTMillis) / pure.AvgRTTMillis * 100
		out = append(out, fmt.Sprintf("Packed vs Pure avg RTT: %.4f ms → %.4f ms (%.1f%%)", pure.AvgRTTMillis, packed.AvgRTTMillis, deltaPct))
	}
	if pure.DurationMillis > 0 && packed.DurationMillis > 0 {
		deltaPct := (pure.DurationMillis - packed.DurationMillis) / pure.DurationMillis * 100
		out = append(out, fmt.Sprintf("Packed vs Pure duration: %.2f ms → %.2f ms (%.1f%%)", pure.DurationMillis, packed.DurationMillis, deltaPct))
	}
	pureMB := float64(pure.PeakHeapInuseBytes) / 1024.0 / 1024.0
	packedMB := float64(packed.PeakHeapInuseBytes) / 1024.0 / 1024.0
	if pureMB > 0 && packedMB > 0 {
		out = append(out, fmt.Sprintf("Packed vs Pure peak heap(inuse): %.2f MB → %.2f MB (%+.2f MB)", pureMB, packedMB, packedMB-pureMB))
	}
	return out
}

func findByContains(results []bench.ProtocolResult, needle string) (bench.ProtocolResult, bool) {
	for _, r := range results {
		if strings.Contains(r.Name, needle) {
			return r, true
		}
	}
	return bench.ProtocolResult{}, false
}

func writeHTML(outPath string, vm viewModel) error {
	tpl, err := template.New("page").Funcs(template.FuncMap{
		"hb":   func(b int64) string { return humanBytes(float64(b)) },
		"mb":   func(b uint64) string { return fmt.Sprintf("%.2f", float64(b)/1024.0/1024.0) },
		"hbps": func(bps float64) string { return humanBps(bps) },
		"f2":   func(f float64) string { return fmt.Sprintf("%.2f", f) },
		"f4":   func(f float64) string { return fmt.Sprintf("%.4f", f) },
		"protoClass": func(name string) string {
			switch {
			case strings.Contains(name, "iotbci-sudoku-packed"):
				return "proto sudoku packed"
			case strings.Contains(name, "iotbci-sudoku"):
				return "proto sudoku"
			case strings.Contains(name, "pure-aead"):
				return "proto pure-aead"
			case strings.Contains(name, "coap"):
				return "proto coap"
			case strings.Contains(name, "dtls"):
				return "proto dtls"
			case strings.Contains(name, "mqtt"):
				return "proto mqtt"
			default:
				return "proto other"
			}
		},
		"toJSON": func(v any) template.JS {
			b, err := json.Marshal(v)
			if err != nil {
				return template.JS("null")
			}
			return template.JS(b)
		},
		"sorted": func(in []bench.ProtocolResult) []bench.ProtocolResult {
			cp := append([]bench.ProtocolResult(nil), in...)
			sort.Slice(cp, func(i, j int) bool { return cp[i].Name < cp[j].Name })
			return cp
		},
		"guessFromCapture": func(sc scenarioReport) string {
			if sc.Capture == nil || sc.Capture.ReportJSON == nil {
				return ""
			}
			if v, ok := sc.Capture.ReportJSON["protocol_guess"].(string); ok {
				return v
			}
			if v, ok := sc.Capture.ReportJSON["ProtocolGuess"].(string); ok {
				return v
			}
			return ""
		},
	}).Parse(pageHTML)
	if err != nil {
		return err
	}

	f, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer f.Close()
	return tpl.Execute(f, vm)
}

const oldPageHTML = `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{.Title}}</title>
  <style>
    :root{
      --bg:#0b1020; --card:#111a33; --text:#e8eeff; --muted:#b7c1e6;
      --border:rgba(255,255,255,.08); --shadow:0 10px 30px rgba(0,0,0,.35);
      --accent:#7c4dff; --good:#39d98a; --warn:#ffcc00; --bad:#ff5a5f;
    }
    body{margin:0; font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial; background:radial-gradient(900px 400px at 10% 0%, rgba(124,77,255,.35), transparent 60%), var(--bg); color:var(--text);}
    a{color:#a9b6ff; text-decoration:none}
    a:hover{text-decoration:underline}
    header{padding:28px 22px 10px; max-width:1180px; margin:0 auto}
    h1{margin:0 0 6px; font-size:22px; letter-spacing:.2px}
    .sub{color:var(--muted); font-size:13px}
    .wrap{max-width:1180px; margin:0 auto; padding:12px 22px 40px}
    .grid{display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:14px}
    @media (max-width: 980px){ .grid{grid-template-columns:1fr} }
    .card{background:linear-gradient(180deg, rgba(255,255,255,.06), rgba(255,255,255,.02)); border:1px solid var(--border); border-radius:16px; box-shadow:var(--shadow); padding:14px 14px}
    .card h2{margin:0 0 10px; font-size:14px; color:var(--muted); font-weight:600}
    .kpi{display:flex; align-items:baseline; gap:10px}
    .kpi .v{font-size:28px; font-weight:800}
    .kpi .u{font-size:13px; color:var(--muted)}
    .pill{display:inline-block; padding:3px 9px; border-radius:999px; font-size:12px; color:#0b1020; background:rgba(124,77,255,.95); font-weight:700}
    .section{margin-top:18px}
    .section h3{margin:14px 0 10px; font-size:16px}
    table{width:100%; border-collapse:collapse; font-size:13px; overflow:hidden}
    th,td{padding:10px 10px; border-bottom:1px solid var(--border); vertical-align:top}
    th{color:var(--muted); text-align:left; font-weight:700}
    tr:hover td{background:rgba(255,255,255,.03)}
    code{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace; background:rgba(255,255,255,.06); padding:2px 6px; border-radius:8px}
    .muted{color:var(--muted)}
  </style>
</head>
<body>
  <header>
    <h1>{{.Title}}</h1>
    <div class="sub">Generated: <code>{{.Now}}</code>{{if .Bench}} · Bench results loaded{{end}}{{if .Evidence}} · Evidence results loaded{{end}}{{if .Attack}} · Attack results loaded{{end}}</div>
  </header>
  <div class="wrap">
    {{if .Bench}}
    <div class="section">
      <h3>Micro-bench Summary</h3>
      <div class="grid">
        <div class="card">
          <h2>Lowest Overhead</h2>
          <div class="kpi"><div class="v">{{f2 .BenchSummary.LowestOverheadRatio}}x</div><div class="u"><span class="pill">{{.BenchSummary.LowestOverheadName}}</span></div></div>
        </div>
        <div class="card">
          <h2>Lowest Avg RTT</h2>
          <div class="kpi"><div class="v">{{f4 .BenchSummary.LowestRTTMs}}</div><div class="u">ms · <span class="pill">{{.BenchSummary.LowestRTTName}}</span></div></div>
        </div>
        <div class="card">
          <h2>Memory (Heap In-Use)</h2>
          <div class="kpi"><div class="v">{{f2 .BenchSummary.LowestMemMB}}</div><div class="u">MB · <span class="pill">{{.BenchSummary.LowestMemName}}</span></div></div>
          <div class="muted" style="margin-top:8px">Avg duration: {{f2 .BenchSummary.AvgDurationMs}} ms · Max Sys: {{f2 .BenchSummary.MaxSysMemMB}} MB</div>
        </div>
      </div>
      {{if .BenchInsights}}
      <div class="card" style="margin-top:14px">
        <h2>Automated Notes</h2>
        <div class="muted">
          {{range .BenchInsights}}<div>• {{.}}</div>{{end}}
        </div>
      </div>
      {{end}}

      <div class="card" style="margin-top:14px">
        <h2>Results</h2>
        <table>
          <thead>
            <tr>
              <th>Protocol</th>
              <th>Overhead</th>
              <th>Avg RTT</th>
              <th>P95 RTT</th>
              <th>Wire Bytes</th>
              <th>Entropy</th>
              <th>Peak Heap (InUse)</th>
              <th>Duration</th>
            </tr>
          </thead>
          <tbody>
            {{range (sorted .Bench.Results)}}
            <tr>
              <td><code>{{.Name}}</code></td>
              <td>{{f2 .OverheadRatio}}x</td>
              <td>{{f4 .AvgRTTMillis}} ms</td>
              <td>{{f4 .P95RTTMillis}} ms</td>
              <td>{{.WireBytesTotal}}</td>
              <td>{{f4 .WireEntropy}}</td>
              <td>{{mb .PeakHeapInuseBytes}} MB</td>
              <td>{{f2 .DurationMillis}} ms</td>
            </tr>
            {{end}}
          </tbody>
        </table>
        <div class="muted" style="margin-top:10px">Tip: for appearance metrics based on real loopback traffic, use <code>cmd/iotbci-evidence -capture_iface ...</code> + per-scenario pcap reports.</div>
      </div>
    </div>
    {{end}}

    {{if .Evidence}}
    <div class="section">
      <h3>Evidence Summary (Loopback TCP/UDP)</h3>
      <div class="grid">
        <div class="card">
          <h2>Lowest Overhead</h2>
          <div class="kpi"><div class="v">{{f2 .EvidenceSummary.LowestOverheadRatio}}x</div><div class="u"><span class="pill">{{.EvidenceSummary.LowestOverheadName}}</span></div></div>
        </div>
        <div class="card">
          <h2>Lowest Avg RTT</h2>
          <div class="kpi"><div class="v">{{f4 .EvidenceSummary.LowestRTTMs}}</div><div class="u">ms · <span class="pill">{{.EvidenceSummary.LowestRTTName}}</span></div></div>
        </div>
        <div class="card">
          <h2>Memory (Heap In-Use)</h2>
          <div class="kpi"><div class="v">{{f2 .EvidenceSummary.LowestMemMB}}</div><div class="u">MB · <span class="pill">{{.EvidenceSummary.LowestMemName}}</span></div></div>
          <div class="muted" style="margin-top:8px">Avg duration: {{f2 .EvidenceSummary.AvgDurationMs}} ms · Max Sys: {{f2 .EvidenceSummary.MaxSysMemMB}} MB</div>
        </div>
      </div>
      {{if .EvidenceInsights}}
      <div class="card" style="margin-top:14px">
        <h2>Automated Notes</h2>
        <div class="muted">
          {{range .EvidenceInsights}}<div>• {{.}}</div>{{end}}
        </div>
      </div>
      {{end}}

      <div class="card" style="margin-top:14px">
        <h2>Scenarios</h2>
        <table>
          <thead>
            <tr>
              <th>Scenario</th>
              <th>Overhead</th>
              <th>Avg RTT</th>
              <th>P95 RTT</th>
              <th>Wire Bytes</th>
              <th>Peak Heap (InUse)</th>
              <th>Capture</th>
              <th>Guess</th>
            </tr>
          </thead>
          <tbody>
            {{range .Evidence.Scenarios}}
            <tr>
              <td><code>{{.Name}}</code></td>
              <td>{{f2 .Metrics.OverheadRatio}}x</td>
              <td>{{f4 .Metrics.AvgRTTMillis}} ms</td>
              <td>{{f4 .Metrics.P95RTTMillis}} ms</td>
              <td>{{.Metrics.WireBytesTotal}}</td>
              <td>{{mb .Metrics.PeakHeapInuseBytes}} MB</td>
              <td>
                {{if .Capture}}
                  {{if .Capture.Enabled}}
                    {{if .Capture.Error}}
                      <span class="muted">error: {{.Capture.Error}}</span>
                    {{else}}
                      <a href="{{.Capture.ReportDir}}/report.html">pcap report</a>
                    {{end}}
                  {{else}}
                    <span class="muted">disabled</span>
                  {{end}}
                {{else}}
                  <span class="muted">n/a</span>
                {{end}}
              </td>
              <td>{{guessFromCapture .}}</td>
            </tr>
            {{end}}
          </tbody>
        </table>
        <div class="muted" style="margin-top:10px">Note: protocol guessing is computed by <code>cmd/iotbci-report</code> based on pcap payload features.</div>
      </div>
    </div>
    {{end}}

    {{if .Attack}}
    <div class="section">
      <h3>Threat Simulation</h3>
      <div class="card">
        <h2>Attack Scenarios</h2>
        <table>
          <thead>
            <tr>
              <th>Scenario</th>
              <th>Success</th>
              <th>Duration</th>
              <th>Expected</th>
              <th>Server Error</th>
              <th>Client Error</th>
            </tr>
          </thead>
          <tbody>
            {{range .Attack.Scenarios}}
            <tr>
              <td><code>{{.Name}}</code></td>
              <td>{{if .Success}}<span class="pill" style="background:rgba(57,217,138,.95)">PASS</span>{{else}}<span class="pill" style="background:rgba(255,90,95,.95)">FAIL</span>{{end}}</td>
              <td>{{f2 .DurationMs}} ms</td>
              <td class="muted">{{.Expected}}</td>
              <td class="muted">{{.ServerError}}</td>
              <td class="muted">{{.ClientError}}</td>
            </tr>
            {{end}}
          </tbody>
        </table>
        <div class="muted" style="margin-top:10px">Generated by <code>cmd/iotbci-attack</code>.</div>
      </div>
    </div>
    {{end}}
  </div>
</body>
</html>`

func fatal(err error) {
	_, _ = fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}

func humanBytes(n float64) string {
	abs := math.Abs(n)
	switch {
	case abs < 1024:
		return fmt.Sprintf("%.0f B", n)
	case abs < 1024*1024:
		return fmt.Sprintf("%.2f KB", n/1024)
	case abs < 1024*1024*1024:
		return fmt.Sprintf("%.2f MB", n/1024/1024)
	default:
		return fmt.Sprintf("%.2f GB", n/1024/1024/1024)
	}
}

func humanBps(bps float64) string {
	return humanBytes(bps) + "/s"
}
