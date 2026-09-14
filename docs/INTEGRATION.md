# Integrating VEXViper with BOMHort

This document records how VEXViper couples to BOMHort, which API contract it relies on,
and what an upstream integration could look like.

## 1. Integration model

BOMHort (`backend/`, Go 1.25, stdlib HTTP, ClickHouse) exposes **no plugin mechanism**:
no Go `plugin` loading, no gRPC/webhook hooks, no MCP. Its contribution guidelines require
stdlib-only tests, discourage frameworks and ask contributors to *ask first* before adding
Go dependencies. VEXViper needs `openvex/go-vex`, the MCP Go SDK, `packageurl-go` and
`yaml.v3`, so the correct integration is an **out-of-tree sidecar speaking the public REST
API** (`docs/api-reference` calls this "custom tooling"). Benefits:

* zero changes to BOMHort; survives the announced 1.0 API freeze;
* independent release cadence and security review of LLM code;
* deployable next to BOMHort (CronJob/Deployment) or on a developer laptop (stdio MCP).

## 2. API contract used

| Call | Purpose | Client method |
|---|---|---|
| `GET /health` | readiness | `Healthy` |
| `GET /api/v1/sboms?page&page_size&search` | enumerate SBOMs (watch mode, `--sbom` lookup by id / `document_name` / `source_file`) | `ListSBOMs`, `AllSBOMs`, `FindSBOM` |
| `GET /api/v1/sboms/{id}/vulnerabilities` | **the findings**: `vuln_id`, `purl`, `severity`, `summary`, `fixed_version`, `vex_status` | `Vulnerabilities` |
| `GET /api/v1/sboms/{id}/dependencies` | dependency tree → direct/transitive evidence | `Dependencies` |
| `GET /api/v1/sboms/{id}/download` | original SBOM → repository hints only (VCS external refs, root PURLs, main Go module) | `DownloadSBOM` |
| `POST /api/v1/sboms/upload` + `X-Filename: <name>.openvex.json` + `X-API-Key` | ingest the generated document | `UploadVEX` |
| `GET /api/v1/vex/statements` | verify ingestion (`--wait`) | `VEXStatements` |

Rate limit (100 req / 10 s) is respected by the client's paging and there is no polling
tighter than `--wait`'s 2 s interval.

### Matching rules that shape the output

BOMHort applies a VEX statement to a finding when `statement.vuln_id == finding.vuln_id`
**and** `statement.product_purl == finding.purl` — plain string equality. Therefore every
statement VEXViper emits:

* uses `vulnerability.name = finding.vuln_id` (exactly as BOMHort returned it, e.g. `GO-2025-…`
  or `GHSA-…`, whatever BOMHort chose as primary id);
* uses `products[0].@id = finding.purl` **and** `products[0].identifiers.purl = finding.purl`
  (BOMHort reads `identifiers.purl` first, then `@id`);
* never normalises, re-encodes or re-qualifies the PURL.

Only OpenVEX is supported by BOMHort, hence only OpenVEX is emitted.

### Upload requirements

* `AUTH_ENABLED=true` with `API_KEYS=…` (or `SERVICE_TOKEN`) on the api-gateway;
* the gateway must be able to write `SBOM_DIR/pushed/` (or use the S3 `skipScan` bucket);
* the ingestion-watcher picks the file up and the parsing-worker applies it; typical
  latency in the E2E stack is 5–20 s. `vexviper generate --upload --wait 3m` polls
  `/api/v1/vex/statements` until the document's statements appear.

## 3. Deployment next to BOMHort

`deploy/helm/vexviper` renders

* `mode: cronjob` (default) — `vexviper watch --once` every 6 h, state and repo cache on an
  optional PVC. Idempotent: an SBOM is re-processed only when its
  `vuln_count@ingested_at` fingerprint changes or `--regenerate` is set.
* `mode: deployment` — continuous poller.
* `mode: mcp` — `mcp-serve --transport http` behind a ClusterIP Service so agents/LLM hosts
  in the cluster can run interactive triage.

Secrets: one Secret with `api-key` (BOMHort) and optionally `openai-api-key`.

## 4. Safety posture

* Default provider is **heuristic**; it can only produce `not_affected` when govulncheck
  proves the vulnerable symbol unreachable. LLM providers are opt-in.
* LLM claims of `not_affected`/`fixed` without deterministic evidence are downgraded to
  `under_investigation` unless explicitly allowed.
* Upload is opt-in; the default is a reviewable file. `author_role` and `status_notes` are
  transparent about automation and confidence.
* No SBOM content is sent anywhere except to the configured provider; with `heuristic`
  nothing leaves the machine besides the git clone and OSV lookups.

## 5. Proposed upstream issue (seebom-labs/BOMHort)

> **Title:** Document VEXViper as a VEX-generation companion; expose `vex_justification` in the vulnerabilities API
>
> BOMHort can consume OpenVEX but has no way to produce it, so every finding stays
> effective until a human writes VEX. [VEXViper](https://github.com/mfahlandt/VEXViper) is
> an out-of-tree Go sidecar that reads `/api/v1/sboms/{id}/vulnerabilities`, resolves the
> product repository, runs govulncheck/collects evidence, asks a configurable assessment
> provider (rules / OpenAI-compatible / MCP tool) and uploads a go-vex-validated OpenVEX
> document via `/api/v1/sboms/upload`. Verified against BOMHort's own 0.6.1 SBOM (9/9
> statements applied).
>
> Proposals:
> 1. Add a `docs/integrations/vexviper` page (I can open the PR).
> 2. Return `vex_justification` and `vex_status_notes` alongside `vex_status` in
>    `/api/v1/sboms/{id}/vulnerabilities` so overlays (#255) and reviewers can see *why*
>    a statement was applied.
> 3. Make the ingestion result observable: an endpoint (or a field on the upload response)
>    that reports whether a pushed `*.openvex.json` was applied and to how many findings —
>    today clients must poll `/api/v1/vex/statements`.
> 4. (Optional) accept `X-Filename` documents with a `vexviper` tooling marker in the
>    "companion OpenVEX" export planned in #255 so generated and hand-written statements can
>    be distinguished.

## 6. Known limitations

* Repository resolution depends on SBOM quality: syft `dir:` SBOMs of Go repos resolve
  (VCS ref / main module); `pkg:generic/<name>@<ver>` roots without VCS refs need `--repo`.
* govulncheck covers Go only. Other ecosystems get version-based evidence and OSV context,
  so without an LLM they end as `under_investigation`.
* The heuristic provider never claims `affected` without govulncheck reachability.
