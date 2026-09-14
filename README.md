# VEXViper

**LLM-assisted OpenVEX generation for [BOMHort](https://bomhort.dev).**

BOMHort ingests SBOMs, matches them against OSV and applies OpenVEX statements — but it
cannot *produce* VEX. Every CVE stays "effective" until somebody hand-writes an OpenVEX
document. VEXViper closes that loop:

```
BOMHort findings ──► resolve product repo ──► clone + govulncheck + evidence
      ▲                                              │
      │                                              ▼
      └──── upload ◄── validated OpenVEX ◄── assessment (heuristic | OpenAI-compatible | MCP tool)
```

1. reads the vulnerability findings BOMHort already computed for an SBOM (`vuln_id`, `purl`,
   `fixed_version`, `vex_status`, …) — BOMHort is the **single source of truth**, VEXViper
   does not rescan anything;
2. resolves the product's source repository (from the SBOM's VCS metadata / PURLs, or
   `--repo owner/name@ref`), clones it shallowly and gathers **deterministic evidence**:
   installed vs fixed version, direct/transitive depth, `govulncheck` reachability for Go
   products, symbol references, OSV details;
3. asks an assessment provider for `status/justification/confidence/reasoning` per finding —
   a rules-only **heuristic** (default, offline), any **OpenAI-compatible** endpoint, or a
   tool on a **configurable MCP server**;
4. applies guardrails and emits an OpenVEX document built with
   [`openvex/go-vex`](https://github.com/openvex/go-vex) whose every statement passes
   `Statement.Validate()` and reuses BOMHort's `(vuln_id, purl)` verbatim so BOMHort's
   exact-match join applies it;
5. optionally uploads it through `POST /api/v1/sboms/upload` and waits until BOMHort shows
   the new `vex_status`.

It is also an **MCP server** itself, so an LLM host (Claude Desktop, VS Code/Copilot, an
agent) can drive or review the triage interactively.

## Status

`examples/bomhort-0.6.1.openvex.json` was generated end-to-end against a real BOMHort
instance from BOMHort's own release SBOM: 9 findings → 9 statements → BOMHort applied all
9 (`6× not_affected` backed by govulncheck, `3× under_investigation` for npm components
where no reachability evidence exists). See [E2E](#end-to-end-test-against-bomhort).

## Why a sidecar over REST (and not an in-tree plugin)

| Fact about BOMHort | Consequence |
|---|---|
| No plugin API (no Go plugins, gRPC hooks, webhooks, MCP) — the REST API is the only extension surface | VEXViper is an out-of-tree Go module talking to `/api/v1` |
| Contribution policy: stdlib-only, "ask first" for new dependencies, no frameworks | go-vex + MCP SDK cannot go into the core module |
| VEX ↔ vulnerability join is exact string equality on `(vuln_id, product_purl)` | statements copy the API's `purl`/`vuln_id`, product `@id` = PURL |
| Upload needs `AUTH_ENABLED=true`, `X-API-Key`, `X-Filename: *.openvex.json`, writable `SBOM_DIR/pushed/` | `--upload` is opt-in; default is a draft file |
| Issue [#255](https://github.com/seebom-labs/BOMHort/issues/255) plans a companion-OpenVEX export | VEXViper's output is exactly that overlay, generated instead of hand-written |

Details: [docs/INTEGRATION.md](docs/INTEGRATION.md).

## Runtime model — one binary, three modes

| Mode | Command | When | Deploy as |
|---|---|---|---|
| **One-shot** | `vexviper generate --sbom … [--repo …] [--upload]` | CI job after publishing an SBOM, manual triage, `make vex` | binary / container step |
| **Watcher** | `vexviper watch [--once] [--upload]` | keep every SBOM in BOMHort covered; re-runs when an SBOM's `vuln_count@ingested_at` fingerprint changes | Kubernetes **CronJob** (`--once`, recommended) or Deployment via the [Helm chart](deploy/helm/vexviper) |
| **MCP server** | `vexviper mcp-serve --transport stdio\|http` | let a host LLM/agent list findings, fetch evidence, draft, and upload VEX with a human in the loop | stdio from an IDE / Claude Desktop, or HTTP Service in the cluster |

Recommendation: run the **CronJob** with the heuristic provider first (no keys, no false
`not_affected` without govulncheck evidence), review drafts, then switch `llm.provider` to
`openai` or `mcptool` and enable `vex.upload`.

## Quick start

```sh
make build                                   # → bin/vexviper (needs Go ≥ 1.25 (image uses 1.26), git; govulncheck optional)

# assess one SBOM already known to BOMHort, write ./bomhort-0.6.1.vexviper.openvex.json
bin/vexviper generate --bomhort http://localhost:8080 --sbom bomhort-0.6.1

# repository cannot be derived from the SBOM? tell VEXViper
bin/vexviper generate --sbom kubelb-1.4.2 --repo kubermatic/kubelb@v1.4.2

# push it back and wait until BOMHort applied the statements
BOMHORT_API_KEY=… bin/vexviper generate --sbom bomhort-0.6.1 --upload --wait 3m

# watch everything, once (CronJob style)
bin/vexviper watch --config examples/vexviper.yaml --once --upload

# be an MCP server for your LLM host
bin/vexviper mcp-serve --config vexviper.yaml                      # stdio
bin/vexviper mcp-serve --transport http --addr 127.0.0.1:8765       # streamable HTTP at /mcp
```

Output filename: `<sbom-name>.vexviper.openvex.json`. Findings that already carry a
`vex_status` are skipped unless `--regenerate`. `--only CVE-…,GHSA-…` restricts the run.

Docker: `docker build -t vexviper . && docker run --rm -v $PWD/work:/work -e VEXVIPER_BOMHORT_URL=http://host:8080 vexviper generate --sbom …`
(the image ships git + Go toolchain + govulncheck).

## Configuration

`--config vexviper.yaml` (see the fully commented [examples/vexviper.yaml](examples/vexviper.yaml)),
every key overridable by `VEXVIPER_<SECTION>_<KEY>` and secrets via `*_env` indirections:

| Key | Env | Default | Meaning |
|---|---|---|---|
| `bomhort.url` | `VEXVIPER_BOMHORT_URL` | `http://localhost:8080` | BOMHort API gateway |
| `bomhort.api_key_env` | `BOMHORT_API_KEY` | | X-API-Key for uploads |
| `llm.provider` | `VEXVIPER_LLM_PROVIDER` | `heuristic` | `heuristic` \| `openai` \| `mcptool` |
| `llm.min_confidence` | `VEXVIPER_LLM_MIN_CONFIDENCE` | `0.6` | below → `under_investigation` |
| `llm.openai.{base_url,model,api_key_env}` | `VEXVIPER_OPENAI_*` | OpenAI / `gpt-4o-mini` | any OpenAI-compatible endpoint (Azure, GitHub Models, Ollama, vLLM, LiteLLM) |
| `llm.mcp.{transport,command,args,url,tool}` | `VEXVIPER_MCP_*` | stdio / `assess_vulnerability` | the MCP server + tool VEXViper calls |
| `repo.{cache_dir,override,clone,govulncheck}` | `VEXVIPER_REPO_*` | `.vexviper-cache`, clone+govulncheck on | product repo handling |
| `vex.{author,author_role,supplier,namespace,out_dir,upload,regenerate}` | `VEXVIPER_VEX_*` | `VEXViper`, `automated triage (LLM-assisted)` | document metadata & output |
| `watch.{interval,state_file}` | `VEXVIPER_WATCH_*` | `15m` | poller |
| `timeout` | `VEXVIPER_TIMEOUT` | `30m` | per SBOM |

### Assessment providers

* **heuristic** (default) — no network, no key. `fixed` when installed ≥ `fixed_version`;
  `not_affected/vulnerable_code_not_in_execute_path` (0.85) when govulncheck finds no
  reachable symbol; `affected` (0.9) when it does; otherwise `under_investigation`.
* **openai** — `POST {base_url}/chat/completions` with JSON-schema structured output,
  `temperature 0`. System prompt in [`internal/llm/prompt.go`](internal/llm/prompt.go)
  frames a *conservative* analyst and forbids inventing evidence.
* **mcptool** — VEXViper connects as MCP client (stdio `command`/`args` or streamable HTTP
  `url`) and calls `tool` with

  ```json
  {"system_prompt": "...", "prompt": "<rendered evidence>", "request": {<finding+evidence>}, "schema": {<assessment JSON schema>}}
  ```

  and accepts either `structuredContent` or a JSON text result (code fences tolerated). This
  lets you plug in *any* model behind a server you control (Bedrock, on-prem, an agent).

Non-heuristic providers fall back to the heuristic on error, so a run never fails because
the model is unreachable.

Assessment schema: `status`, `justification`, `impact_statement`, `action_statement`,
`confidence` (0–1), `reasoning`, `evidence_refs[]`.

### Guardrails (always on)

* confidence `< min_confidence` → `under_investigation`;
* `not_affected` requires at least one strong deterministic evidence item (govulncheck
  unreachable, component absent …) unless `allow_unsupported_not_affected: true`;
* `fixed` requires a known `fixed_version` ≤ installed version;
* every statement passes go-vex `Statement.Validate()`; `status_notes` records provider,
  confidence and reasoning; `tooling` records `vexviper/<version> provider=<name>`.

## MCP server

`vexviper mcp-serve` exposes:

| Tool | Purpose |
|---|---|
| `list_sboms` | SBOMs in BOMHort with vuln counts |
| `list_findings` | BOMHort's findings for one SBOM (incl. existing `vex_status`) |
| `get_repo_context` | resolve+clone repo, govulncheck, evidence + ready-made prompt per finding |
| `draft_vex` | build a validated OpenVEX document from assessments the host provides |
| `generate_vex` | run the full pipeline with the configured provider, optionally upload |
| `upload_vex` | push a document to BOMHort |
| `list_vex_statements` | verify BOMHort ingested it |

Host config example: [examples/mcp-client-config.json](examples/mcp-client-config.json).
Typical agent flow: `list_findings` → `get_repo_context` → the host model reasons →
`draft_vex` → human review → `upload_vex` → `list_vex_statements`.

## Development

```sh
make lint          # gofmt + go vet (incl. integration tag)
make test          # go test ./...
make test-race
make e2e           # full BOMHort round trip, see below
```

Tests use only the standard library `testing` package plus `httptest`, in-memory MCP
transports and the reusable fake BOMHort in `internal/bomhort/bomhorttest`. Fixtures under
`testdata/` include BOMHort's release SBOM and recorded OSV responses — unit tests need no
network.

### End-to-end test against BOMHort

`hack/e2e-bomhort.sh` spins up an isolated BOMHort stack
(`hack/docker-compose.e2e.yml`: ClickHouse, api-gateway, ingestion-watcher, parsing-worker
with `AUTH_ENABLED=true`), drops `testdata/bomhort-0.6.1.spdx.json` into its SBOM dir,
runs `vexviper generate --upload --wait`, asserts BOMHort applied every statement, runs
`go test -tags integration ./test/integration/` and copies the result to
`examples/bomhort-0.6.1.openvex.json`.

```sh
BOMHORT_SRC=~/GolandProjects/seebom make e2e          # needs docker compose + locally built seebom-* images
```

Env: `BOMHORT_IMAGE_PREFIX`/`BOMHORT_IMAGE_TAG` to pick images, `--keep` to leave the stack up.

## Layout

```
cmd/vexviper/          CLI (generate | watch | mcp-serve | version)
internal/bomhort/      REST client + bomhorttest fake server
internal/sbom/         minimal SPDX/CycloneDX reader — only for repository hints
internal/repo/         PURL/VCS → repository resolution, shallow git clone cache
internal/evidence/     version compare, dependency depth, govulncheck (multi-module), symbol grep
internal/osv/          OSV vuln detail client (context for the LLM)
internal/llm/          Provider interface, prompt, heuristic | openai | mcptool | mock
internal/vexgen/       assessments → go-vex document, guardrails, validation
internal/pipeline/     orchestration, watch loop
internal/mcpserver/    VEXViper's own MCP server
test/integration/      -tags integration tests against a live BOMHort
hack/                  E2E compose + script
deploy/helm/vexviper/  CronJob | Deployment | MCP Service chart
```

## License

Apache-2.0
