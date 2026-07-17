#!/usr/bin/env python3

from collections.abc import Iterable
from pathlib import Path
import re
from urllib.parse import unquote, urlsplit


LINK_PATTERN = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
FENCE_PATTERN = re.compile(r"^[ \t]{0,3}(`{3,}|~{3,})")
IGNORED_SCHEMES = {"http", "https", "mailto", "tel"}


def _normalize_target(raw_target: str) -> str | None:
    target = raw_target.strip()
    if target.startswith("<") and ">" in target:
        target = target[1 : target.index(">")]
    else:
        target = target.split(maxsplit=1)[0] if target else ""

    if not target:
        return None

    parsed = urlsplit(target)
    if parsed.scheme.lower() in IGNORED_SCHEMES or parsed.netloc:
        return None

    target = unquote(parsed.path)
    if not target:
        return None
    return target


def extract_local_links(path: Path) -> list[tuple[int, str]]:
    links: list[tuple[int, str]] = []
    active_fence: tuple[str, int] | None = None

    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        fence_match = FENCE_PATTERN.match(line)
        if fence_match:
            marker = fence_match.group(1)
            if active_fence is None:
                active_fence = (marker[0], len(marker))
            elif (
                marker[0] == active_fence[0]
                and len(marker) >= active_fence[1]
                and not line[fence_match.end() :].strip()
            ):
                active_fence = None
            continue

        if active_fence is not None:
            continue

        for link_match in LINK_PATTERN.finditer(line):
            target = _normalize_target(link_match.group(1))
            if target is not None:
                links.append((line_number, target))

    return links


def find_broken_links(
    root: Path,
    markdown_paths: Iterable[Path],
) -> list[str]:
    root = root.resolve()
    broken_links: set[str] = set()

    for markdown_path in markdown_paths:
        source = markdown_path if markdown_path.is_absolute() else root / markdown_path
        source = source.resolve()
        try:
            source_relative = source.relative_to(root).as_posix()
        except ValueError as error:
            raise ValueError(f"Markdown source is outside repository: {source}") from error

        for line_number, target in extract_local_links(source):
            destination = (source.parent / target).resolve()
            try:
                destination.relative_to(root)
            except ValueError:
                is_broken = True
            else:
                is_broken = not destination.exists()

            if is_broken:
                broken_links.add(f"{source_relative}:{line_number} -> {target}")

    return sorted(broken_links)
