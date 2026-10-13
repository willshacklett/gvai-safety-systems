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

## Deployment boundary

This pull request does not configure a hosting provider, GitHub Pages workflow, custom domain, CNAME, DNS, or Railway. For a future approved deployment, CI should run the same allowlisted builder from a reviewed GitHub commit and publish only `dist/public-site` as a static artifact. Hosting should remain replaceable. Do not connect the public page to the source API until tenant identity, resource ownership lookup, authorization, and independent enforcement are integrated and reviewed.