# Progress Checklist (Against Proposal & Schedule)

This repository implements a secure transport enhancement for BCI-IoT scenarios (AEAD + handshake + Sudoku-based appearance obfuscation + optional mux/UoT), and provides reproducible benchmarking, capture analysis, and attack simulations.

Use this checklist to verify the “deliverables” described in the proposal PDF and the schedule PDF.

## Protocol design & documentation

- [x] Threat model (replay / MITM / resource abuse): `doc/SECURITY.md`
- [x] Protocol spec (handshake/session/record/obfs layers): `doc/SPEC.md`, `doc/HANDSHAKE.md`, `doc/STATE_MACHINE.md`
- [x] Sudoku obfuscation design notes: `doc/OBFS_SUDOKU.md`

## Core implementation

- [x] Identity/auth + key schedule (Ed25519): `pkg/iotbci/*`, `doc/HANDSHAKE.md`
- [x] AEAD record layer: `pkg/iotbci/recordconn.go`
- [x] Obfuscation layer (Sudoku encode/padding/layout rotation): `pkg/obfs/sudoku/*`
- [x] Optional mux + UoT (datagram over stream): `pkg/iotbci/mux/*`, `pkg/iotbci/uot/*`
- [ ] Fuzz testing report (parsers/decoders/state machine)

## Benchmarking & evaluation

- [x] Baselines: pure-AEAD / CoAP-over-UDP / MQTT / DTLS: `internal/bench/run_*.go`
- [x] End-to-end bench runner (JSON output): `cmd/iotbci-bench`
- [x] Wire “appearance” metrics (size/time bins, throughput, write syscalls): `internal/bench/wire*.go`
- [x] Entropy metrics (byte distribution / length entropy) integrated into reports
- [ ] Extreme-network evaluation (high jitter/loss/peak-hour style) as reproducible script/config

## Capture analysis & attack simulation

- [x] Capture workflow: `doc/CAPTURE.md`
- [x] Protocol fingerprinting from pcap (DTLS/CoAP/MQTT/pure-AEAD/Sudoku): `cmd/iotbci-report`
- [x] Attack simulations (replay / MITM tamper / flood probes): `cmd/iotbci-attack`

## Reproducibility & release hygiene

- [x] Deployment notes: `doc/DEPLOYMENT.md`
- [x] Git remotes / “Gitea full vs GitHub template-only”: `doc/GIT_REMOTES.md`, `scripts/sync_github_branch.sh`
- [x] CI script/workflow to run `go test ./...` and `go test -race ./...`: `.github/workflows/{ci,stress}.yml`
- [x] Remove local artifacts from the repo (bench JSON / dashboards / evidence outputs): `.gitignore`
