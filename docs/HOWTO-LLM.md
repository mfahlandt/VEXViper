# How to: set up an LLM provider (OpenAI-compatible, GitHub Models, Copilot)

Goal: VEXViper asks a language model for the verdict instead of using only the
built-in rules, with a spend cap, and the model's answer still passes the
deterministic guardrails.

The provider only sees the evidence VEXViper collected (govulncheck result,
dependency depth, lockfile graph, OSV data). A `not_affected` without strong
evidence is always downgraded to `under_investigation`, whatever the model says.

## Prerequisites

* VEXViper working with `provider: heuristic` (see
  [How to: run VEXViper as a CronJob](HOWTO-CRONJOB.md)).
* One of:
  * an **OpenAI-compatible endpoint** and key (OpenAI, Azure OpenAI, Ollama, vLLM, LiteLLM …);
  * a **GitHub account with a Copilot subscription** — for GitHub Models a
    fine-grained PAT with the `models: read` permission (billed to the plan);
  * the **GitHub Copilot CLI** installed and logged in on the machine that runs
    VEXViper (laptop or CI runner — the VEXViper container image does not ship it).

## Steps

Pick one provider.

### A. OpenAI-compatible endpoint

1. Configure:

   ```yaml
   llm:
     provider: openai
     min_confidence: 0.6
     openai:
       base_url: https://api.openai.com/v1     # Ollama: http://localhost:11434/v1
       model: gpt-4o-mini
       api_key_env: OPENAI_API_KEY
       timeout: 120s
   ```

2. Export the key and run:

   ```sh
   export OPENAI_API_KEY=…
   vexviper generate --sbom my-service.cdx.json --provider openai
   ```

   Helm: put the key into the secret key `openai-api-key`; the chart wires it to
   `OPENAI_API_KEY`.

### B. GitHub Models with a Copilot subscription (works in CronJobs and CI)

1. Create a fine-grained personal access token with **Account permissions →
   Models: Read-only**. In GitHub Actions the workflow token works with
   `permissions: models: read`.

2. Configure:

   ```yaml
   llm:
     provider: github
     github:
       model: openai/gpt-4.1-mini     # any id from https://github.com/marketplace/models
       token_env: GITHUB_TOKEN
   ```

3. Run:

   ```sh
   export GITHUB_TOKEN=…
   vexviper generate --sbom my-service.cdx.json --provider github
   ```

   Helm: secret key `github-token` → `GITHUB_TOKEN`; set
   `config.llm.provider: github` in `values.yaml`.

### C. GitHub Copilot CLI (laptop or CI runner, no API key)

1. Install and log in once (`copilot`, then `/login`), or let it use `gh`:

   ```sh
   gh auth login
   export GH_TOKEN=$(gh auth token)
   copilot --version
   ```

2. Configure:

   ```yaml
   llm:
     provider: copilot
     copilot:
       command: copilot
       # model: gpt-5          # empty = CLI default
       in_repo: true           # Copilot may read the cloned product code (never write)
       timeout: 180s
   ```

3. Run:

   ```sh
   vexviper generate --sbom my-service.cdx.json --provider copilot
   ```

   VEXViper starts `copilot -p … -s --output-format json --no-ask-user
   --deny-tool=shell --deny-tool=write --deny-tool=edit` per finding (about 15 s
   each) and bills **premium requests** to your Copilot seat.

### Cap the spend

Whichever provider: set a budget per run (CLI) or per watch pass (CronJob).
Findings beyond the cap are *deferred* — no statement, SBOM not marked done —
and picked up by the next pass.

```yaml
llm:
  budget:
    max_calls: 200
    max_tokens: 0               # OpenAI / GitHub Models
    max_premium_requests: 50    # Copilot CLI
```

Keep `cache.enabled: true` (default). Identical questions (same model, product
commit, vulnerability, package and evidence) reuse the stored verdict instead of
paying again.

## Verify

* The CLI summary ends with `provider usage: N calls, … tokens, … premium
  requests, model=…`; the per-finding `assessed` log lines show
  `provider=openai|github|copilot` instead of `heuristic`.
* Statements in the document carry the model's `justification` and
  `impact_statement`; a downgraded one has the original verdict in `status_notes`.
* `vexviper watch` writes the lifetime usage to the state file
  (`usage`, `last_pass_usage`); in `mode: deployment` the same numbers are on
  `/metrics`.

## When it does not work

* **All verdicts come from `heuristic` although a provider is set** — the
  provider failed and VEXViper fell back. The log has the error: wrong
  `base_url`, missing env var (`api_key_env`/`token_env` name, not the value),
  or a model id the endpoint does not know.
* **`401`/`403` from GitHub Models** — the PAT lacks `models: read`, or the
  organisation has disabled GitHub Models.
* **Copilot CLI hangs or asks a question** — an old CLI without `--no-ask-user`;
  update it. `copilot` not found: set `copilot.command` to the full path.
* **Many `under_investigation` despite the model saying `not_affected`** —
  expected without strong evidence (no govulncheck result, no lockfile graph).
  Give VEXViper the repository (`repo.sboms` pins) so it can collect evidence;
  do not set `allow_unsupported_not_affected`.
* **Budget hit every pass** — raise `max_calls`, or look at cache hits in the
  usage line: a changing product commit on every run defeats the cache.

Reference: [README – Assessment providers](../README.md#assessment-providers),
[Integration – using a Copilot subscription](INTEGRATION.md#7-using-a-github-copilot-subscription-as-llm-source).
