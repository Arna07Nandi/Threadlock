# Threadlock — Autonomous Deal Chief of Staff (India + Global)

Production-ready monorepo combining:
- **Bond × Apple × Muse Web UI** (`web/index.html`) served directly by FastAPI at `/`
- **ANIMA Bitemporal Deal-Memory Graph** (`engine/bitemporal_graph.py`) with Read-Set Slicing & SHA-256 `StateSnapshot`
- **Proof-Carrying Neuro-Symbolic Business Math & Tax Kernel** (`engine/symbolic_verifier.py`) with exact integer-paise math, India GST (SAC 998361, ₹20L threshold, CGST+SGST vs IGST) & TDS (194J / 194C / W-8BEN), Margin Floor Guard, Idempotency-Key deduplication, and Ed25519 hash-chained audit logs
- **Dual-Speed Pipeline** (`engine/dual_speed_pipeline.py`) for sub-millisecond Live Stealth HUD + Async 8:00 AM Morning Brief
- **Zero-Friction Connectors** (`integrations/connectors.py`) for WhatsApp, Gmail, Slack, and 1-Click 90-Day History Import
- **Tauri v2 Rust Stealth Overlay** (`desktop/tauri_stealth_hud.rs`) for `NSWindowSharingNone` / `WDA_EXCLUDEFROMCAPTURE`

## Quick Start
```bash
pip install -r requirements.txt
uvicorn api.server:app --reload --port 8000
```

## Run the 500-Scenario Real-World Benchmark
```bash
python3 benchmarks/real_world_benchmark.py
```
