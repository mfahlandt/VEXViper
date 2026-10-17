# How to: run VEXViper as a CronJob against your BOMHort

Goal: VEXViper runs every few hours in your cluster, assesses every new BOMHort
finding, uploads OpenVEX statements, and you can see them applied in BOMHort.

## Prerequisites

* A BOMHort ≥ 0.7 api-gateway reachable from the cluster with `AUTH_ENABLED=true`
  and an API key (or service token) that may upload.
* `helm` 3 and `kubectl` against the target cluster.
* The source repositories of your products reachable from the cluster (public
  GitHub works out of the box; private hosts need a token, see step 3).

## Steps

1. Create the namespace and the secret. The chart reads `api-key`; `github-token`
   is optional and only needed for GitHub Models or private clones.

   ```sh
   kubectl create namespace vexviper
   kubectl -n vexviper create secret generic vexviper \
     --from-literal=api-key="$BOMHORT_API_KEY"
   ```

2. Write `values.yaml`. The heuristic provider needs no key and is the safe
   baseline; switch to an LLM later with [How to: set up an LLM provider](HOWTO-LLM.md).

   ```yaml
   mode: cronjob
   schedule: "0 */6 * * *"
   bomhort:
     url: http://bomhort-api-gateway.bomhort.svc:8080
     existingSecret: vexviper
   upload: true
   persistence:
     enabled: true          # keeps repo clones, verdict cache and watch state between runs
     size: 10Gi
   config:
     llm:
       provider: heuristic
     watch:
       reassess_after: 168h # re-check open verdicts weekly; not_affected/fixed stay closed
       concurrency: 2
   ```

3. Map SBOMs to repositories when BOMHort has no `source_repo` for them. VEXViper
   first uses the SBOM's `source_repo`/`source_ref` from BOMHort, then VCS hints in
   the SBOM, then these pins. `match` is compared with the SBOM id, document name
   and file name (glob allowed); `{version}` expands from the file name.

   ```yaml
   config:
     repo:
       sboms:
         - match: "kubelb-*"
           repo: kubermatic/kubelb
         - match: "my-service.cdx.json"
           repo: https://gitlab.example.com/team/my-service@release-{version}
   ```

   Private https clones use `GITHUB_TOKEN` from the secret key `github-token`
   (`kubectl -n vexviper create secret generic vexviper --from-literal=api-key=… --from-literal=github-token=…`).

4. Install the chart.

   ```sh
   helm install vexviper oci://ghcr.io/seebom-labs/charts/vexviper \
     -n vexviper -f values.yaml
   ```

5. Run the first pass now instead of waiting for the schedule.

   ```sh
   kubectl -n vexviper create job --from=cronjob/vexviper vexviper-first
   kubectl -n vexviper logs -f job/vexviper-first
   ```

   The log ends with one `assessed` line per finding (`vuln`, `purl`, `status`,
   `confidence`) and an `uploaded` line per SBOM.

## Verify

1. BOMHort shows the statements on the SBOM. Every finding VEXViper handled now
   carries `vex_status`, and `vex_tooling` starts with `vexviper/`:

   ```sh
   curl -s -H "X-API-Key: $BOMHORT_API_KEY" \
     "$BOMHORT_URL/api/v1/sboms/<sbom-id>/vulnerabilities" \
     | jq '.[] | {vuln_id, purl, vex_status, vex_tooling}'
   ```

   In the BOMHort UI the SBOM's vulnerability list shows the VEX badge and the
   `under_investigation` / `not_affected` counts move.

2. The next run skips what is already done. Trigger a second job and look for
   `skipped` in the summary; nothing should be re-assessed unless `reassess_after`
   expired. Verdicts written by people (any other `vex_tooling`) are never touched.

## When it does not work

* **`401` on upload** — the key in the secret is not accepted. Check the chart
  `NOTES.txt` warning and that BOMHort runs with `AUTH_ENABLED=true` and this key.
* **Every statement is `under_investigation`** — VEXViper could not clone the
  product repository (`repo unavailable` in the log). Add a pin in step 3 or set
  `source_repo` on the SBOM in BOMHort (`PATCH /api/v1/sboms/{id}`).
* **Statements uploaded but `vex_status` stays empty** — the statement did not
  match. VEXViper matches on the exact `vuln_id` + `purl` BOMHort returned; run
  `vexviper generate --sbom <id> --upload --wait 2m` from a laptop to get a per-
  statement applied/not-matched report.
* **Run takes longer than `timeout` (30 m)** — raise `config.timeout` or lower
  `watch.concurrency`; govulncheck on large Go modules is the usual cost.
* **Costs** — `vexviper_findings_*` metrics exist only in `mode: deployment`;
  for CronJobs read the usage summary at the end of the job log.

Reference: [README](../README.md), [Integration](INTEGRATION.md).
