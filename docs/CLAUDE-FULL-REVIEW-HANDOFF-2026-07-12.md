# Claude full-review handoff: GigaWiper detection as code

- **Review snapshot:** July 12, 2026
- **Publication update:** July 13, 2026
- **Timezone:** America/Chicago
- **Primary workspace:** `C:\Codex`
- **Lab repository:** `C:\Codex\gigawiper-detection-as-code`
- **Companion site repository:** `C:\Codex\nine-lives-zero-trust`
- **Review mode:** independent, comprehensive, and read-only unless the user later authorizes fixes

> **Post-review remediation:** Codex subsequently implemented the confirmed
> local fixes. The native workflow is manual/confirmation-gated, the telemetry
> root is created, NLS-GW-001 and NLS-GW-005 are hardened, exact-query fixtures
> now contain five positive and five negative cases, the native and Graph
> writers share a cross-workflow concurrency lock, and the read-only live
> synthetic runner passed all ten. The resulting lab and companion-site changes
> were pushed to draft PRs #4 and #339, with their required checks passing. As
> of the July 13 publication update, the branch preview is
> `https://agent-gigawiper-detection-as.nine-lives-zero-trust.pages.dev`.
> Historical review-state sections below are retained as provenance and are
> labeled accordingly; use fresh `git` and `gh` reads for current state.

The raw 9.4 MB review transcript is intentionally excluded from both
repositories because its API output contains tenant, subscription, and account
identifiers. Keep that transcript local and do not publish it.

## Copy-paste starter for Claude

Use this exact starter message when opening the review in Claude:

> You are the independent final reviewer for the GigaWiper detection-as-code
> project. Work inside the existing `C:\Codex` environment. Read
> `C:\Codex\gigawiper-detection-as-code\docs\CLAUDE-FULL-REVIEW-HANDOFF-2026-07-12.md`
> completely before taking any action, then follow every instruction in it.
> Review the two repositories, both pull requests, every changed file, every
> detection and test, the live lab evidence, the Defender and Sentinel portal
> state available in the signed-in environment, the article, and every diagram
> and screenshot. Treat the handoff as a navigation aid: independently verify
> each claim and distinguish observation from inference. This is a review, not
> a cleanup or deployment task. Preserve all
> existing working-tree changes, do not commit or push, and do not mutate the
> tenant, endpoint, alerts, incidents, rules, identities, roles, workflows, or
> Azure resources. Report findings first with file/line or portal evidence,
> then verified claims, unresolved questions, test results, and separate
> merge/publication verdicts for the lab and blog PRs.

Everything below records the archival review scope.

## Mission

Perform an independent, evidence-led end-to-end review of the project as if it
were about to be published as a technically rigorous detection-engineering
case study. Review:

1. detection logic and KQL correctness;
2. Bicep and preview-resource contracts;
3. PowerShell deployment, inspection, testing, and safe-telemetry code;
4. GitHub Actions, OIDC, permissions, sequencing, and safety boundaries;
5. the distinction between native Repository failure, Graph fallback state,
   and portal-native alert evidence;
6. live Defender XDR, Sentinel, Azure, and endpoint evidence where the current
   signed-in environment permits read-only inspection;
7. every factual and editorial claim in the article and lab catalog;
8. every diagram, portal screenshot, rendered evidence graphic, social image,
   and responsive thumbnail;
9. local tests, site builds, PR status, checks, stacking, and working-tree
   scope; and
10. whether each PR is ready to merge or publish.

Do not merely summarize. Look for inconsistencies, assumptions, unsafe
defaults, unsupported claims, stale text, missing negative evidence, misleading visual
labels, weak provenance, and places where a passing test does not prove the
claim being made.

## Non-negotiable evidence boundaries

These boundaries must remain intact in any review or proposed edit. Verify them
independently and identify any proposed change in scope.

1. There are exactly **three portal-native Defender custom alerts**:
   `NLS-GW-LIVE-001`, `NLS-GW-LIVE-003`, and `NLS-GW-LIVE-004`.
2. `NLS-GW-002` is **synthetic-only**. No recovery disablement, boot-policy
   change, permission attack, raw-disk operation, or wipe command ran.
3. `NLS-GW-005` matched live telemetry and its exact aggregation, but it has
   **no saved portal rule and no alert**. The portal wizard stopped at
   `Supported entities could not be loaded`; no root cause is assigned.
4. Do not attribute an alert or incident to any of the six Graph-fallback
   objects. Graph exact-ID read-back and scheduler metadata are not alert
   attribution.
5. Native Sentinel Repository synchronization failed. Its root cause is
   **unconfirmed**. Do not convert the evidence into either a success claim or
   a confirmed Microsoft defect.
6. The three portal-native validation rules are different objects from the six
   Graph-fallback IDs and from the failed native Repository deployment path.
7. The separate built-in Defender alert `System executable renamed and
   launched` is Microsoft-managed EDR evidence, not a GigaWiper-family alert and
   not one of the three custom alerts.
8. No GigaWiper or FlockWiper sample ran. No malware, encryption, wiping,
   recovery disablement, destructive boot changes, actual MinIO transfer, C2, or
   off-host data transfer occurred.
9. Preserve unrelated and pre-existing working-tree changes. Never use
   `git reset --hard`, `git checkout --`, `git clean`, blanket line-ending
   normalization, or automatic formatting across unrelated files.
10. This review does not authorize cleanup, commits, pushes, workflow
    dispatches, portal edits, role assignments, or resource deletion.

## Exact positive alert evidence

All three alert-detail pages were observed as **Custom detection** from
**Microsoft Defender for Endpoint**, tied to device `nls-gw-lab`, with no
response actions taken.

| Portal rule | Rule number | Alert ID | Severity/category | Evaluation evidence |
|---|---:|---|---|---|
| `NLS-GW-LIVE-001` | `152` | `ede0f56adf-2532-41c2-98a8-ac08a2481201_aml` | High / Persistence | Recorded initial scheduled evaluation over prior benign telemetry; linked at `09:46:42` in the portal's UTC-5 display |
| `NLS-GW-LIVE-003` | `153` | `ed1f17e8f7-3600-4c97-867e-b6bd1c987c37_aml` | High / Defense Evasion | Recorded initial scheduled evaluation over prior benign telemetry; linked at `10:00:38` UTC-5 |
| `NLS-GW-LIVE-004` | `151` | `eda016b9bd-4631-44d3-baa6-314b4f7ed032_aml` | Medium / Exfiltration / Continuous (NRT) | Portal-native NRT alert whose last activity matched a safe post-rule marker; the marker is not established as its sole cause |

The three alerts were observed correlated into incident `628`:

- exact title: **Multi-stage incident involving Persistence & Exfiltration on
  one endpoint**;
- severity: **High**;
- observed state: **Active**;
- active alerts: **3/3**;
- assets: one device, `nls-gw-lab`;
- response actions: zero on all three custom-alert pages.

## Observed, synthetic, and absent evidence

| Detection | Correct evidence level |
|---|---|
| NLS-GW-001 | Benign scheduled-task and registry telemetry plus a separate portal-native scheduled alert |
| NLS-GW-002 | Synthetic KQL fixtures only |
| NLS-GW-003 | Custom-lab-log clearing telemetry plus a separate portal-native scheduled alert |
| NLS-GW-004 | Harmless `mc.exe` filename/command-line telemetry plus a separate portal-native NRT alert; no transfer occurred |
| NLS-GW-005 | Seven live inert `FileRenamed` events and an exact live query match; no portal rule and no alert |

## Deployment-path evidence

### Native Sentinel Repository path

- Connection: GitHub repository on `main`, content type `CustomDetection`.
- Defender/Sentinel portal state: **Failed**.
- Native runs `29178665606` and `29180501340` failed all six corrected
  templates with outer `InvalidTemplateDeployment` and inner `ProviderError`.
- The connection identity met the documented prerequisites and could read a
  custom rule through Graph.
- A temporary Azure Security Admin diagnostic did not change the outcome and
  was removed.
- The observed prerequisites did not identify a confirmed cause. The
  `ProviderError` records the deployment-stage failure; it does not establish a
  provider defect or an app-only incompatibility.

### Bounded Graph-only fallback

The exact stable IDs are:

1. `nls-gw-000-canary` — disabled;
2. `nls-gw-001-onedrive-persistence` — enabled;
3. `nls-gw-002-recovery-boot-tampering` — enabled;
4. `nls-gw-003-event-log-destruction` — enabled;
5. `nls-gw-004-minio-transfer-staging` — enabled; and
6. `nls-gw-005-candy-rename-burst` — enabled.

The dedicated fallback identity uses environment-scoped GitHub OIDC, no stored
client secret, only the Graph application permission
`CustomDetection.ReadWrite.All`, and zero Azure RBAC assignments. The workflow
is manual, exact-ID only, and has no delete or prune mode.

Important workflow runs:

| Run | Purpose | Expected result |
|---:|---|---|
| `29180371449` | Graph fallback canary | Passed; exact canary disabled and read back |
| `29180593038` | Full Graph fallback | Passed; all six exact IDs returned HTTP 200; canary disabled; five rules enabled; zero recorded actions |
| `29193356536` | Read-only Graph inspection | Passed; six objects read without mutation |
| `29193929962` | Post-telemetry scheduler inspection | Passed; five enabled rules at `PT1H`; common last run `2026-07-12T13:09:25.6533333Z`; next run `2026-07-12T14:09:25.6533333Z`; both current `automatedActions` and deprecated `responseActions` empty |

The canary fallback completed before the native retry. The full-pack fallback
began only after that native retry completed in failure. Native and fallback
deployment runs were not concurrent.

### Portal-list visibility

Before the three portal-native rules existed, an exact `NLS-GW` filter showed
zero rows. A later exact-prefix filter showed exactly the three `LIVE` rules and
still none of the six Graph-fallback objects. The cause of the Graph objects'
absence from that portal list remains unresolved. Do not infer alert ownership
from scheduler metadata or portal-list visibility.

## Historical repository snapshot before remediation

### Lab repository

- Path: `C:\Codex\gigawiper-detection-as-code`
- Branch: `agent/finalize-evidence-ledger`
- Remote PR head: `f2c4af67d44a8cd8efcf37659876c11dd090c168`
- PR: [j-dahl7/gigawiper-detection-as-code#4](https://github.com/j-dahl7/gigawiper-detection-as-code/pull/4)
- Base: `main` at `30b5cd82d80a0f93eb55e31dd2090fa3d68d9cd2`
- State at this snapshot: open, draft, mergeable, seven commits, seven changed
  files, no comments, no reviews, and no review threads.
- Check at this snapshot: `validate` passed in run `29201744618`.

Remote PR files relative to its base:

- `.github/workflows/graph-preview-fallback.yml`
- `README.md`
- `docs/EVIDENCE.md`
- `docs/HANDOFF-2026-07-12.md`
- `scripts/Deploy-CustomDetectionsGraph.ps1`
- `scripts/Invoke-SafeGigaWiperTelemetry.ps1`
- `scripts/Test-Lab.ps1`

### Companion site repository

- Path: `C:\Codex\nine-lives-zero-trust`
- Branch: `agent/gigawiper-detection-as-code`
- Remote PR head: `e533986116c75a691edbeb1debbf8b538886a769`
- PR: [nine-lives-security/nine-lives-zero-trust#339](https://github.com/nine-lives-security/nine-lives-zero-trust/pull/339)
- Stacked base: `agent/lab-catalog-verification` at
  `3214c76b42a6ec8af3a36c8493fdffd7c084bf95`; do not review it as a simple
  `main...HEAD` diff.
- State at this snapshot: open, draft, mergeable, five commits, twenty-four
  changed files, no reviews, and no review threads.
- The only PR conversation comment is the successful Cloudflare Pages bot
  deployment.
- Checks passed: Cloudflare Pages, `build-and-verify` run `29200290107`, and
  `link-check` run `29200290135`.
- Remote preview: `https://2f98066f.nine-lives-zero-trust.pages.dev`
- Branch preview:
  `https://agent-gigawiper-detection-as.nine-lives-zero-trust.pages.dev`

The checks above applied to the named snapshot heads. They did not include the
additional local working-tree changes described next.

## Historical local working-tree snapshot (subsequently published)

At this snapshot, every existing local change was treated as user-owned. Those
project changes were subsequently reviewed, committed, and pushed. This list is
retained to show the review scope; do not treat it as current `git status`
output.

### Lab local changes beyond PR head

`git status --short` reported:

- `M README.md`
- `M docs/EVIDENCE.md`
- `M docs/GRAPH-FALLBACK.md`
- `M scripts/Deploy-CustomDetectionsGraph.ps1`
- `M scripts/Test-Lab.ps1`
- this Claude handoff file is newly added locally.

Important nuance: `docs/GRAPH-FALLBACK.md` was already marked modified because
of line-ending state, but `git diff -- docs/GRAPH-FALLBACK.md` is empty. Do not
normalize or overwrite it.

The intentional local content changes are:

- `README.md` and `docs/EVIDENCE.md`: distinguish the historical zero-row
  portal check from the later exact three-LIVE-rule result, while preserving
  the fact that no Graph-fallback objects appeared;
- `scripts/Deploy-CustomDetectionsGraph.ps1`: apply-time verification and
  result reporting now count both current `automatedActions` and deprecated
  `responseActions`; and
- `scripts/Test-Lab.ps1`: contract checks now require both action models to be
  enforced in inspection and apply modes.

### Companion site local changes beyond PR head

`git status --short` reported:

- `M content/blog/gigawiper-detections-as-code.md`
- `M content/labs/gigawiper-detection-as-code/_index.md`
- `M static/images/blog/gigawiper-detection-as-code/github-fallback-deployment.png`
- `M static/images/blog/gigawiper-detection-as-code/og-gigawiper-dac.png`
- `M static/images/blog/gigawiper-detection-as-code/src/og-gigawiper-dac.html`
- `M static/images/thumbnails/gigawiper-detections-as-code-320.webp`
- `M static/images/thumbnails/gigawiper-detections-as-code-640.webp`
- `M static/images/thumbnails/gigawiper-detections-as-code-960.webp`
- `?? .qa-gigawiper/`

Intentional local changes:

- the Labs entry no longer says portal-native custom-alert evidence is pending;
- the Labs entry now preserves the exact three-alert, NLS-GW-002,
  NLS-GW-005, Graph-attribution, native-failure, and cleanup boundaries;
- the social card says `6 Graph IDs`, not `5 Graph rules`;
- responsive thumbnails were regenerated from the updated social card;
- the fallback screenshot was replaced with a sharper Actions capture that
  visibly includes all six exact IDs, HTTP 200, disabled/enabled states, and
  zero recorded actions; it is normalized to a true 1280x720 PNG; and
- the article caption now explicitly says all six exact-ID updates are visible
  and separately explains the later two-action-model inspector.

`.qa-gigawiper/` is a pre-existing, untracked generated site snapshot: 686
files, approximately 40.6 MB. It must not be deleted, added, or treated as part
of the intended PR without explicit user direction.

## Azure and live-lab environment

The CLI session was observed signed in to an enabled Azure subscription. Do not
copy subscription IDs, tenant IDs, account identifiers, access tokens, cookies,
or secrets into the review report.

Read-only Azure state observed at this snapshot:

- resource group: `nls-gigawiper-dac-lab-rg`;
- region: `eastus`;
- provisioning state: `Succeeded`;
- tags: `Owner=NineLives`, `Purpose=GigaWiperDetectionAsCode`, and
  `Expiration=2026-07-12`;
- endpoint name: `nls-gw-lab`;
- Defender portal previously showed Windows Server 2022, onboarding status
  `Onboarded`, sensor health `Active`, and full security operations;
- default inbound deny is present with zero custom inbound NSG rules; and
- an ARM VM instance-view read was unavailable after three connection-reset
  retries during handoff preparation. Do not interpret that transient API
  failure as evidence that the VM is absent or stopped.

Allowed read-only discovery commands include:

```powershell
az account show --query "{name:name,state:state}" -o json
az group show --name nls-gigawiper-dac-lab-rg `
  --query "{name:name,location:location,tags:tags,provisioningState:properties.provisioningState}" -o json
az vm get-instance-view --resource-group nls-gigawiper-dac-lab-rg `
  --name nls-gw-win-lab --query "instanceView.statuses" -o json
```

Retry transient reads conservatively. Do not start, stop, redeploy, resize, run
commands on, or delete the VM or resource group.

## Read-only portal review sequence

Use the signed-in browser session only if it is already available. Never inspect
cookies, token stores, passwords, or browser profile data. If authentication is
missing, stop and ask the user to sign in rather than bypassing it.

1. Open Microsoft Defender at `https://security.microsoft.com`.
2. Open incident `628` and verify the exact title, High severity, Active state,
   active alerts 3/3, one device, and the three exact `LIVE` alerts.
3. Open each of the three alert-detail pages and verify the exact alert ID,
   detection source `Custom detection`, product/service Microsoft Defender for
   Endpoint, device `nls-gw-lab`, incident `628`, and the explicit no-actions
   message.
4. Open the unified Detection Rules page. Filter exact prefix `NLS-GW` and
   verify exactly three rows, all `NLS-GW-LIVE-001`, `003`, and `004`. Confirm
   there is no LIVE-005 and no visible Graph-fallback display name.
5. Inspect rules `152`, `153`, and `151` read-only. Compare rule `152` with the
   documented NLS-GW-001 validation revision; compare rules `153` and `151`
   with the current NLS-GW-003 and NLS-GW-004 query logic. The hardened current
   NLS-GW-001 revision is intentionally newer. Do not edit or disable the
   rules.
6. Navigate to Microsoft Sentinel > Content management > Repositories. Verify
   the `GigaWiper detection as code` GitHub connection targets `main`, content
   type Custom Detection Rules, and last deployment status Failed. Do not retry
   or reconnect it.
7. Open the `nls-gw-lab` device page. Its current totals may include the
   separate built-in alert and incident `627`; do not miscount those as custom
   evidence.
8. If Advanced Hunting is used, run only read-only queries and do not save or
   convert them into rules. Existing screenshots and the evidence ledger should
   normally be enough.

Do not classify alerts, close the incident, isolate the device, take response
actions, save new rules, edit correlation, or trigger automation.

## Complete lab repository reading order

Read every file below, not only the PR diff:

1. `docs/HANDOFF-2026-07-12.md`
2. `docs/EVIDENCE.md`
3. this Claude handoff
4. `README.md`
5. `SECURITY.md`
6. `docs/GRAPH-FALLBACK.md`
7. all six `detections/NLS-GW-*.bicep` files
8. `hunting/gigawiper-hunts.kql`
9. `tests/synthetic-unit-tests.kql`
10. `infra/lab-endpoint.bicep`
11. `scripts/Test-Lab.ps1`
12. `scripts/Deploy-CustomDetectionsGraph.ps1`
13. `scripts/Invoke-SafeGigaWiperTelemetry.ps1`
14. `scripts/Deploy-Lab.ps1`
15. `scripts/New-LabEndpoint.ps1`
16. `.github/workflows/validate.yml`
17. `.github/workflows/graph-preview-fallback.yml`
18. the generated native workflow
    `.github/workflows/sentinel-deploy-51af5a44-e148-40f0-b250-6457efb89a6c.yml`
19. its paired generated PowerShell workflow helper
    `.github/workflows/azure-sentinel-deploy-51af5a44-e148-40f0-b250-6457efb89a6c.ps1`
20. `.github/CODEOWNERS`, `bicepconfig.json`, and `LICENSE`

The older `docs/HANDOFF-2026-07-12.md` records milestone commit `42a8b6d` in its
publication-state section. The lab PR head at this snapshot was later,
`f2c4af67d44a8cd8efcf37659876c11dd090c168`. Treat the former as a recorded
milestone unless the surrounding wording proves it was intended as the current
head.

## Lab code-review checklist

### Detection and KQL semantics

- Confirm every Bicep query and matching hunt use the intended table, casing,
  time window, projection, and entity columns.
- Review the NLS-GW-001 process/registry correlation for duplicate or missed
  matches and whether the join semantics fit the alert title.
- Confirm NLS-GW-002 destructive behavior patterns appear only in fixtures and detection
  logic, never in executed telemetry code.
- Confirm NLS-GW-003 can clear only the dedicated custom lab log in the safe
  harness.
- Confirm NLS-GW-004 does not perform network transfer and that article wording
  does not upgrade a filename/command-line marker into exfiltration evidence.
- Confirm NLS-GW-005's sliding five-minute correlation, summarize, and entity
  requirements are technically sound while preserving the no-alert
  boundary.
- Compare the saved portal-native query views with the validation revision for
  001 and the current exact queries for 003 and 004 if portal access is
  available; the hardened current 001 revision is intentionally newer.
- Verify required `Timestamp`, `DeviceId`, and `ReportId` handling is scoped to
  this pack rather than presented as a universal custom-detection law.

### Bicep and preview contract

- Check stable ID validity, uniqueness, length, letter-prefixed format, and
  display-name uniqueness.
- Confirm every rule has only the currently accepted single MITRE tactic.
- Check severity, tactics, techniques, schedule, status, alert template, and
  host entity mapping against the evidence and article.
- Confirm the disabled canary stays disabled.
- Confirm there are exactly six resources: one disabled canary and five
  enabled behavior rules.
- Distinguish compiler/schema success from live service acceptance.

### PowerShell and workflow safety

- Trace all apply, inspection, and verification paths in
  `Deploy-CustomDetectionsGraph.ps1`.
- Confirm exact-ID-only behavior, allowed methods/statuses, query preservation,
  no delete/prune path, and no logging of access tokens or secrets.
- Verify the helper that counts actions includes both current
  `automatedActions` properties and deprecated `responseActions` items.
- Verify apply-time assertion and result reporting both use that helper.
- Review null handling, PowerShell collection semantics, error propagation,
  JSON serialization, timestamps, request IDs, and beta Graph model drift.
- Confirm the fallback workflow cannot run automatically, is environment
  scoped, uses OIDC, and is sequenced separately from native synchronization.
- Verify the generated native workflow is preserved as evidence and is not
  misrepresented as passing.
- Review `Invoke-SafeGigaWiperTelemetry.ps1` line by line for scope guards,
  path validation, exact cleanup, harmless marker behavior, and any command
  that could escape the disposable lab boundary.
- Review endpoint Bicep for default inbound deny, zero custom inbound rules,
  onboarding-package handling, identity exposure, and expiration tagging.

### Tests

- Check that `Test-Lab.ps1` tests behavioral contracts in addition to string-
  presence checks.
- Confirm all ten named synthetic results exercise the intended five positive
  and five negative behaviors.
- Verify the action-model contract cannot pass if apply mode checks only the
  deprecated collection.
- Look for untested parsing paths, false positives, false negatives, time-zone
  assumptions, and brittle regexes.

## Companion article and Labs review

Read completely:

- `content/blog/gigawiper-detections-as-code.md`
- `content/labs/gigawiper-detection-as-code/_index.md`
- `scripts/render-gigawiper-dac-assets.js`
- every file under
  `static/images/blog/gigawiper-detection-as-code/`
- the five HTML sources under its `src/` directory; and
- the three `gigawiper-detections-as-code-{320,640,960}.webp` thumbnails.

Review every technical statement against the lab evidence and authoritative
sources. Pay special attention to:

- preview version and prerequisites;
- historical evaluation wording for LIVE-001 and LIVE-003;
- NRT/operator wording and the limited claim for LIVE-004;
- native-failure language and unconfirmed root cause;
- Graph beta limitations, permissions, action-model deprecation, and absence
  of alert attribution;
- NLS-GW-002 and NLS-GW-005 evidence levels;
- the separate built-in alert;
- cleanup instructions and exact object counts;
- whether the article consistently says six Graph IDs/resources, five enabled
  behavior rules, three portal-native alerts, and incident 628;
- whether any screenshot caption accidentally turns historical evidence into
  current state; and
- whether the Labs entry and article agree with `docs/EVIDENCE.md`.

Use primary sources for technical verification: Microsoft Learn, Microsoft
Security Blog, Microsoft Graph documentation, GitHub documentation, and the
actual repository/workflow state. Clearly label inferences.

## Visual and screenshot inventory

### Portal or GitHub captures

- `advanced-hunting-safe-telemetry.png`
- `defender-custom-alert-incident.png` — historical first-alert state, not the
  final 3/3 incident state
- `defender-custom-alert-no-actions.png`
- `defender-custom-detections-no-portal-row.png` — historical pre-LIVE-rule
  zero-row state
- `defender-incident-628-three-alerts.png` — final incident Alerts-tab capture
  with exactly the three portal-native alerts
- `github-fallback-deployment.png` — recropped Actions summary; all
  six IDs now visible
- `github-scheduler-inspection.png`
- `sentinel-repository-native-failed.png`

### Rendered editorial graphics

- `threat-intel-to-git.png` with paired HTML source
- `live-hunting-evidence.png` with paired HTML source
- `portal-three-alert-evidence.png` with paired HTML source; explicitly labeled
  as a rendered summary, not a portal screenshot
- `og-gigawiper-dac.png` with paired HTML source
- `detection-coverage-map.png` with paired HTML source added during the
  post-review remediation

### Responsive social derivatives

- `gigawiper-detections-as-code-320.webp`
- `gigawiper-detections-as-code-640.webp`
- `gigawiper-detections-as-code-960.webp`

## Visual-QA facts already observed

Independently repeat enough of this work to validate it:

- 38 GigaWiper raster assets decoded successfully: 13 PNG masters or captures,
  22 inline WebP derivatives, and three responsive social thumbnails.
- All 11 inline article figures had natural dimensions matching their declared
  `width` and `height` attributes.
- Source canvases were audited at 1600x1000, 1600x950, 1600x1000, 1680x945,
  and 1200x630 with no unintended text clipping or out-of-canvas content. The OG card's
  diagonal slash intentionally extends beyond the canvas and is clipped as a
  decorative effect.
- The article was inspected at 1280x720 in light and dark themes and through a
  390x720 mobile viewport.
- The lab page and blog listing card were inspected at desktop and mobile
  widths.
- Mobile article width remained contained; figures scaled without page-level
  overflow. The lab table uses intentional horizontal scrolling on narrow
  screens.
- The social card and responsive thumbnails preserve the title, GigaWiper
  panel, `6 validation IDs`, `3 portal-native alerts`, incident 628, and the
  alert-attribution boundary.
- `github-fallback-deployment.png` is now a true 1280x720 PNG and visibly shows
  all six rows.
- The eight older raw captures were losslessly normalized from JPEG bytes to
  true PNG containers during the authorized remediation; decoded-pixel SHA-256
  hashes were identical before and after conversion.
- The local image viewer intermittently showed black compositing blocks on the
  first render of some images; a second render and independent Sharp decode
  showed intact files. Treat a repeatable defect as actionable, but do not mistake a
  one-frame viewer paint glitch for file corruption.

For every visual, check:

1. factual accuracy and evidence classification;
2. exact counts, IDs, labels, timestamps, and status;
3. legibility at native size and within the article;
4. cropping, alignment, hierarchy, contrast, spacing, and brand consistency;
5. mobile scaling and whether a tap-to-open link makes dense text recoverable;
6. alt text and caption accuracy;
7. whether portal screenshots and rendered summaries are unmistakably
   distinguished; and
8. whether private or secret data is exposed. Request IDs and lab-only device
   identifiers are not credentials, but no tokens or tenant secrets should
   appear.

Prioritize evidence readability and clear provenance over additional
decoration, glow, or density.

## Commands Claude may run

Start with a non-mutating workspace audit:

```powershell
Set-Location C:\Codex\gigawiper-detection-as-code
git branch --show-current
git rev-parse HEAD
git status --short
git diff --check
git diff -- docs/GRAPH-FALLBACK.md
git diff

Set-Location C:\Codex\nine-lives-zero-trust
git branch --show-current
git rev-parse HEAD
git status --short
git diff --check
git diff
```

Lab validation:

```powershell
Set-Location C:\Codex\gigawiper-detection-as-code
.\scripts\Test-Lab.ps1 -Json
git diff --check
```

Expected current lab result: passed, six detection files, six unique IDs, nine
destructive-string checks, eight telemetry ownership controls, infrastructure
compiled, zero custom inbound security rules, ten positive/negative result
contracts, eleven command-branch contracts, six optimized time-window
contracts, seventeen fallback contracts, and ten workflow contracts.

Companion-site validation must run in this order because a draft preview build
changes the output set expected by the production blog checker:

```powershell
Set-Location C:\Codex\nine-lives-zero-trust
npm run check:labs
npm run build:preview
npm run build
npm run check:blogs
git diff --check
```

Expected current site result:

- Labs catalog: 18 entries;
- preview build: 222 pages;
- production build: 215 pages; and
- rendered blog contract: 20 published posts.

The draft article is intentionally excluded from the production post count.

GitHub read-only checks:

```powershell
gh pr view 4 --repo j-dahl7/gigawiper-detection-as-code `
  --json number,title,state,isDraft,mergeable,headRefOid,reviewDecision,statusCheckRollup,comments,reviews
gh pr checks 4 --repo j-dahl7/gigawiper-detection-as-code

gh pr view 339 --repo nine-lives-security/nine-lives-zero-trust `
  --json number,title,state,isDraft,mergeable,headRefOid,reviewDecision,statusCheckRollup,comments,reviews
gh pr checks 339 --repo nine-lives-security/nine-lives-zero-trust
```

Do not run any of these without new explicit authorization:

- `scripts/Deploy-Lab.ps1`
- `scripts/New-LabEndpoint.ps1`
- `scripts/Invoke-SafeGigaWiperTelemetry.ps1`
- apply mode in `scripts/Deploy-CustomDetectionsGraph.ps1`
- any workflow dispatch or re-run
- any portal create/edit/delete/disable/enable operation
- any Azure start/stop/deploy/delete/role operation
- any cleanup command
- any commit, push, merge, or PR mutation.

## Required review output

Return a self-contained report in this order:

1. **Findings**, ordered by severity: blocker, high, medium, low, then nit.
   Each finding must name the repository, file and line or exact portal/run
   evidence, explain impact, distinguish observation from inference, and give
   a narrowly scoped recommendation.
2. **Verified evidence matrix** covering all six Graph IDs, all five behavior
   detections, all three portal-native alerts, incident 628, native failure,
   scheduler metadata, the built-in alert, NLS-GW-002, and NLS-GW-005.
3. **Code and security review** for Bicep, KQL, PowerShell, workflows, OIDC,
   permissions, response-action models, safe telemetry, endpoint scope, and
   cleanup.
4. **Live-lab review** stating exactly what was re-observed, what could not be
   re-observed, and any transient access failures. Do not present an unavailable
   API read as a negative platform result.
5. **Editorial and source review** listing every claim that is fully supported,
   overstated, stale, ambiguous, or dependent on preview behavior.
6. **Visual review** for every listed asset, including portal-versus-rendered
   classification, dimensions, legibility, cropping, mobile behavior, and alt
   text.
7. **Validation results** with exact commands and outcomes.
8. **Working-tree scope audit** confirming that no existing change was lost or
   overwritten.
9. **Separate verdicts** for lab PR #4 and blog PR #339: ready, ready after
   named local changes are published, or not ready, with reasons.
10. **Proposed next actions**, but do not implement them unless the user gives
    separate authorization.

If there are no findings, say so explicitly, but still provide the verified
evidence matrix, limitations, and verdicts. Never use a lack of findings as a
substitute for describing what was actually inspected.

## Canonical source files

The primary internal evidence sources are:

- `docs/HANDOFF-2026-07-12.md`
- `docs/EVIDENCE.md`
- `README.md`
- `docs/GRAPH-FALLBACK.md`
- the six detection Bicep files;
- the hunting and synthetic KQL files;
- the PowerShell and workflow implementations;
- the companion article and Labs page; and
- the saved visuals in the companion repository.

The handoffs tell Claude where to look. The code, retained workflow output,
portal state, screenshots, and authoritative documentation determine whether a
claim is actually verified.
