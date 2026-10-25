# Public Website Foundation

## What this slice is

The repository root `index.html` is the GVAI Safety Systems public-facing informational site. It describes experimental work and planned GVAI Intelligence audiences; it has no login, model calls, data submission, API requests, live agent tools, or production shutdown interface.

The page reuses the small `web/gv-carl-logo.svg` mark from `willshacklett/GvAI` under its MIT license; the notice is included at `assets/GvAI-MIT-LICENSE.txt`. The research plot at `examples/gv_geometry_map.png` is an existing Safety Systems artifact and is explicitly identified as static experimental research. The larger source Cesium application was not copied because it loads Cesium, ArcGIS imagery, GIS data services, and Railway-backed routes.

## Local build and test

No frontend package installation or build tool is required. Prepare a deterministic output using the checked-in asset allowlist:

```sh
python scripts/prepare_public_site.py --output dist/public-site
python -m unittest discover -s tests -p 'test_public_site.py'
python -m http.server 8080 --bind 127.0.0.1 --directory dist/public-site
```

Then open `http://127.0.0.1:8080/`. The builder requires an empty output directory and copies only the allowlisted public files; it does not publish the dashboard, API configuration, data directories, or repository contents generally.

## Prototype-stage customer inquiries

The homepage audience cards and contact section offer **Business - Request a Demonstration**
and **Government - Request a Technical Briefing** actions. Both open the visitor's
email application at `contact@gvaisafety.com`, with distinct percent-encoded subject
lines. The address is also visible and copyable for visitors without a configured
email application. The recorded demo links back to the homepage contact section.

These are inquiries about experimental work, not an offer of production services,
customer deployments, or operational safety guarantees. Visitors are instructed not
to email classified, sensitive, or confidential operational information. Email is
not a secure operational reporting channel.

The website has no contact form, backend, external API, customer-data storage,
analytics, tracking, or new network dependencies. Sending email is a separate
visitor action handled by their email application and mail provider; the website
does not submit or store the message. No worker, supervisor, deployment workflow,
or static deployment allowlist changes are required.

For review, check both inquiry subjects, keyboard focus, and button wrapping at
320px, 375px, 680px, and desktop widths. Do not send a test email unless separately
authorized. The contact changes alone do not activate hosting or satisfy the
maintainer deployment gates below.

## Deployment boundary

This pull request does not configure a hosting provider, GitHub Pages workflow, custom domain, CNAME, DNS, or Railway. For a future approved deployment, CI should run the same allowlisted builder from a reviewed GitHub commit and publish only `dist/public-site` as a static artifact. Hosting should remain replaceable. Do not connect the public page to the source API until tenant identity, resource ownership lookup, authorization, and independent enforcement are integrated and reviewed.

## Controlled GitHub Pages deployment proposal

The proposed `.github/workflows/deploy-public-site.yml` runs only on pushes to `main` or a manual dispatch whose ref is `main`, and only in this repository. Its validation job runs the repository and website suites, then builds with `scripts/prepare_public_site.py`; `actions/upload-pages-artifact` receives only `dist/public-site`. The deploy job requires that validation job, uses the `github-pages` environment, checks the Pages API reports `build_type: workflow`, and deploys the artifact through the official pinned Pages actions. It has no pull-request or fork publish trigger. Concurrency does not cancel a deployment already in progress.

### Read-only legacy Pages exposure audit

At audit time, the Pages API reported public legacy publishing from `main` at `/`. HTTP HEAD requests returned `200` for representative paths including `README.md`, `SECURITY.md`, `pyproject.toml`, `requirements.txt`, `docs/architecture.md`, `dashboard/index.html`, `dashboard/data/kv_index.json`, `data/sample_combined.csv`, `outputs/sample_irreversible_enriched.csv`, `outputs/sample_irreversible_summary.json`, `tests/test_identity.py`, and `scripts/prepare_public_site.py`. These are representative confirmed paths, not an exhaustive listing of everything Pages serves.

The path `experiments/agent_safety/pilot_input/request.txt` also returned `200`; its response body was deliberately not fetched or inspected. Its content classification is therefore unknown and must be reviewed by an authorized maintainer before changing the Pages source. No secret values were retrieved or confirmed in this audit. A `200` for these paths confirms public availability, not that their contents are confidential; the repository itself is also public on GitHub.

**Do not merge or activate this workflow until the manual gates below are complete.** The repository currently uses GitHub Pages legacy publishing from `main` at `/`. Any main push while that remains configured can republish repository-root files independently of this workflow. Before merging the deployment workflow PR, a maintainer must review the exposure inventory above and switch **Settings → Pages → Build and deployment → Source** to **GitHub Actions**. The workflow preflight fails closed if the source is still `legacy`, but that check cannot disable the existing legacy publisher by itself.

### Required maintainer settings before activation

1. Protect `main`: require pull requests, at least one independent human approval, and the successful `tests` check. Direct pushes and force pushes should be blocked. These settings were not readable with the audit integration and need maintainer verification.
2. In **Settings → Pages**, switch the source from branch/root publishing to **GitHub Actions** before merging the workflow PR. Confirm the source no longer says `legacy`; do not add a CNAME or change DNS as part of this step.
3. In **Settings → Environments → github-pages**, require approval from an independent human reviewer, restrict deployments to `main`, and disable administrator bypass where GitHub allows it. The current environment API showed a `main` branch policy but no required-reviewer rule, and administrator bypass was enabled. Update and verify these settings before any production run.
4. Confirm the deployment run shows the expected reviewed `main` commit, passes `tests` and `test_public_site.py`, creates the allowlisted artifact, waits for environment approval, and then deploys that artifact only.

GitHub Actions' `GITHUB_TOKEN` is limited to read contents in validation and `pages: write` plus `id-token: write` in the gated deploy job. Third-party actions are pinned to full commit SHAs. No provider credentials or model keys are used.

### Rollback

Rollback through a reviewed revert on `main` and the same validated Pages workflow, with the `github-pages` human approval still required. Rebuild the previous approved site from its Git commit using the allowlisted builder. Do not switch back to legacy branch/root publishing as a shortcut. If the Pages source or environment controls cannot be verified, stop publishing and have a maintainer repair those settings before retrying. Keep `gvai.io` unchanged until a separately approved and verified domain migration.
