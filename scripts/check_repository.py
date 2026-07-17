#!/usr/bin/env python3

import argparse
from collections.abc import Iterable
import hashlib
from pathlib import Path
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.curriculum import write_manifest
from scripts.markdown_links import find_broken_links


BASELINE_PATH = Path("content/known-broken-links.txt")
FROZEN_BASELINE_RECORDS_SHA256 = (
    "f9494547093a8069b4953ca990fc01370d830b9520331a89e68fde525476d382"
)
REQUIRED_LOCALIZED = (
    Path("README.md"),
    Path("start-here.md"),
    Path("paths.md"),
    Path("setup/windows.md"),
    Path("setup/linux.md"),
    Path("setup/macos.md"),
    Path("safety/lab-safety.md"),
)
FORBIDDEN_LOCALIZED_SUFFIXES = {
    ".c",
    ".h",
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".a",
    ".lib",
}
FORBIDDEN_LOCALIZED_FILENAMES = {"Makefile"}
EXCLUDED_MARKDOWN_DIRECTORIES = {"venv"}


def compare_link_failures(
    current: Iterable[str],
    baseline: Iterable[str],
) -> tuple[list[str], list[str]]:
    current_records = set(current)
    baseline_records = set(baseline)
    return (
        sorted(current_records - baseline_records),
        sorted(baseline_records - current_records),
    )


def repository_markdown_paths(root: Path) -> list[Path]:
    return sorted(
        (
            path
            for path in root.rglob("*.md")
            if not any(part.startswith(".") for part in path.relative_to(root).parts)
            and not EXCLUDED_MARKDOWN_DIRECTORIES.intersection(
                path.relative_to(root).parts
            )
        ),
        key=lambda path: path.relative_to(root).as_posix(),
    )


def current_broken_links(root: Path) -> list[str]:
    return find_broken_links(root, repository_markdown_paths(root))


def read_link_baseline(root: Path) -> list[str]:
    path = root / BASELINE_PATH
    if not path.is_file():
        return []
    return sorted(
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    )


def link_baseline_is_frozen(root: Path) -> bool:
    path = root / BASELINE_PATH
    if not path.is_file():
        print(f"Frozen link baseline is missing: {BASELINE_PATH.as_posix()}")
        return False

    normalized_records = "\n".join(read_link_baseline(root)).encode("utf-8")
    digest = hashlib.sha256(normalized_records).hexdigest()
    if digest != FROZEN_BASELINE_RECORDS_SHA256:
        print(
            "Frozen link baseline changed. Fix broken links instead of adding "
            "exceptions to content/known-broken-links.txt."
        )
        return False
    return True


def check_links(root: Path) -> bool:
    if not link_baseline_is_frozen(root):
        return False

    current = current_broken_links(root)
    baseline = read_link_baseline(root)
    new_records, resolved_records = compare_link_failures(current, baseline)

    if resolved_records:
        print(
            f"{len(resolved_records)} baseline records are resolved; "
            "the immutable snapshot remains unchanged"
        )

    if new_records:
        print("New broken links:")
        for record in new_records:
            print(record)
        return False

    legacy_count = len(set(current).intersection(baseline))
    print(f"No new broken links; {legacy_count} legacy records remain")
    return True


def check_locales(root: Path) -> bool:
    errors: list[str] = []
    for relative_path in REQUIRED_LOCALIZED:
        for locale in ("fr", "en"):
            path = root / locale / relative_path
            if not path.is_file():
                errors.append(f"Missing localized foundation path: {path.relative_to(root)}")

    copied_code = sorted(
        (
            path.relative_to(root).as_posix()
            for locale in ("fr", "en")
            for path in (root / locale).rglob("*")
            if path.is_file()
            and (
                path.suffix.lower() in FORBIDDEN_LOCALIZED_SUFFIXES
                or path.name in FORBIDDEN_LOCALIZED_FILENAMES
            )
        )
    )
    errors.extend(f"Localized tree contains a code copy: {path}" for path in copied_code)

    if errors:
        print("Localized foundation check failed:")
        for error in errors:
            print(error)
        return False

    print("Localized foundation paths are complete and contain no code copies")
    return True


def check_manifest(root: Path) -> bool:
    manifest = root / "content/curriculum.json"
    overrides = root / "content/status-overrides.json"
    with tempfile.TemporaryDirectory() as directory:
        generated = Path(directory) / "curriculum.json"
        write_manifest(root, generated, overrides)
        expected = generated.read_bytes()

    if not manifest.is_file() or manifest.read_bytes() != expected:
        print("content/curriculum.json is stale; regenerate it with scripts/curriculum.py")
        return False

    print("content/curriculum.json matches the generated curriculum inventory")
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description="Check repository foundations")
    parser.add_argument(
        "--check-links",
        action="store_true",
        help="fail only for failures absent from the baseline",
    )
    parser.add_argument(
        "--check-locales",
        action="store_true",
        help="validate required FR/EN foundation paths and forbid code copies",
    )
    parser.add_argument(
        "--check-manifest",
        action="store_true",
        help="regenerate and compare content/curriculum.json",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="run every non-mutating check",
    )
    arguments = parser.parse_args()

    if not any(vars(arguments).values()):
        parser.error("select at least one repository check")

    success = True
    if arguments.check_links or arguments.all:
        success = check_links(ROOT) and success
    if arguments.check_locales or arguments.all:
        success = check_locales(ROOT) and success
    if arguments.check_manifest or arguments.all:
        success = check_manifest(ROOT) and success

    raise SystemExit(0 if success else 1)


if __name__ == "__main__":
    main()
