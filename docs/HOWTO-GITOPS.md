# How to: review VEX drafts in pull requests before they reach BOMHort

Goal: every VEX document VEXViper produces lands as a pull request in a git
repository; a human reviews and merges it, and only merged statements are
uploaded to BOMHort.

## Prerequisites

* A git repository for the statements, e.g. `github.com/acme/vex-statements`,
  with a base branch (`main`) that is protected so bots cannot merge.
* A GitHub token with `contents: write` and `pull_requests: write` on that
  repository (fine-grained PAT or a GitHub App installation token). For GitHub
  Enterprise Server note the API URL (`https://ghe.example.com/api/v3`).
* VEXViper installed (CLI or Helm, see [How to: run VEXViper as a CronJob](HOWTO-CRONJOB.md)).

## Steps

1. Configure the publishing target. CLI (`vexviper.yaml`):

   ```yaml
   vex:
     upload: false            # nothing goes to BOMHort before review
     git:
       enabled: true
       repo: https://github.com/acme/vex-statements.git
       branch: main
       path: vex              # directory inside the repo
       branch_prefix: vexviper/
       pr: true
       token_env: GITHUB_TOKEN
       sign_off: true         # DCO trailer on the bot commits
       # api_url: https://ghe.example.com/api/v3
   ```

   Helm (`values.yaml`), token in the secret key `github-token`:

   ```yaml
   upload: false
   git:
     enabled: true
     repo: https://github.com/acme/vex-statements.git
     branch: main
     path: vex
     branchPrefix: vexviper/
     pr: true
     signOff: true
   ```

   ```sh
   kubectl -n vexviper create secret generic vexviper \
     --from-literal=api-key="$BOMHORT_API_KEY" \
     --from-literal=github-token="$GITHUB_TOKEN"
   ```

2. Run once for one SBOM to see the flow.

   ```sh
   export GITHUB_TOKEN=…
   vexviper generate --sbom my-service.cdx.json --git
   ```

   VEXViper clones the repository into `<repo.cache_dir>/gitops`, rebuilds the
   branch `vexviper/<product-slug>` from `main`, writes
   `vex/<name>.vexviper.openvex.json`, commits, force-pushes the branch and opens
   a pull request with a review checklist. Running again for the same product
   updates the same PR; identical content produces no new commit.

3. Review the PR. Each statement carries `status`, `justification`, the evidence
   VEXViper used and the confidence; `under_investigation` with the original
   model verdict in `status_notes` means a guardrail blocked a `not_affected`
   that had no deterministic proof. Edit the file in the PR if needed, then merge.

4. Upload merged documents. Merging does not talk to BOMHort. Add a job in the
   statements repository that uploads whatever reaches `main`:

   ```yaml
   # .github/workflows/upload.yml in acme/vex-statements
   on:
     push:
       branches: [main]
       paths: ["vex/**"]
   jobs:
     upload:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v4
         - run: |
             for f in vex/*.openvex.json; do
               sbom=$(jq -r '.statements[0].products[0]["@id"]' "$f")
               curl -fsS -X POST "$BOMHORT_URL/api/v1/sboms/upload?sbom_id=$sbom" \
                 -H "X-API-Key: $BOMHORT_API_KEY" \
                 -H "X-Filename: $(basename "$f")" \
                 --data-binary @"$f"
             done
           env:
             BOMHORT_URL: ${{ vars.BOMHORT_URL }}
             BOMHORT_API_KEY: ${{ secrets.BOMHORT_API_KEY }}
   ```

   `products[0].@id` of every statement is the BOMHort SBOM id, so the job can
   scope the upload exactly like VEXViper does (`?sbom_id=`).

5. Switch to the schedule: `vexviper watch --git` (CLI) or the Helm values from
   step 1. Set `upload: true` as well if you also want an immediate, unreviewed
   copy in BOMHort and the PRs only as audit trail.

## Verify

* The statements repository has one open PR per product named after the branch
  `vexviper/<product-slug>`, opened by the token's identity.
* After a merge, the upload job is green and the SBOM in BOMHort shows
  `vex_status` on the covered findings (`GET /api/v1/sboms/{id}/vulnerabilities`).
* A second VEXViper run against an unchanged product logs no new commit.

## When it does not work

* **`push` fails with 403** — the token lacks `contents: write`, or the branch
  `vexviper/*` is protected. Bot branches must stay unprotected; only `main` is.
* **PR is not opened** — `pr: true` needs `pull_requests: write`; on GHES set
  `api_url`. The push itself still happened, check the branch.
* **Token in logs?** — VEXViper passes the token through `GIT_CONFIG_*`
  environment variables and redacts it from errors; if you see one, report it.
* **`branch_prefix: ""`** commits straight to `main` without a PR. Only use it
  when the repository is itself the review step (e.g. a mirrored audit log).

Reference: [README – Review-first GitOps mode](../README.md#review-first-gitops-mode-vexgit),
[Integration – safety posture](INTEGRATION.md).
