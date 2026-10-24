from __future__ import annotations

import argparse
import shutil
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PUBLIC_FILES = (
    "index.html",
    "site.css",
    "assets/gvai-mark.svg",
    "assets/GvAI-MIT-LICENSE.txt",
    "examples/gv_geometry_map.png",
    "prototype-demo.html",
    "prototype-demo.css",
    "prototype-demo.js",
)


def prepare_site(destination: Path) -> Path:
    destination = Path(destination)
    if destination.exists():
        if destination.is_symlink() or not destination.is_dir():
            raise ValueError("Public site output must be a directory.")
        if any(destination.iterdir()):
            raise ValueError("Public site output directory must be empty.")
    else:
        destination.mkdir(parents=True)

    for relative_path in PUBLIC_FILES:
        source = REPOSITORY_ROOT / relative_path
        target = destination / relative_path
        if source.is_symlink() or not source.is_file():
            raise ValueError(f"Missing or unsafe public asset: {relative_path}")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)

    return destination


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Prepare the allowlisted GVAI Safety Systems static site."
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("dist/public-site"),
        help="Empty output directory (default: dist/public-site).",
    )
    args = parser.parse_args()
    output = prepare_site(args.output)
    print(f"Prepared static site in {output}")


if __name__ == "__main__":
    main()
