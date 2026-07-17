from contextlib import redirect_stdout
import io
from pathlib import Path
import tempfile
import unittest

from scripts.markdown_links import extract_local_links, find_broken_links
from scripts.check_repository import (
    REQUIRED_LOCALIZED,
    check_links,
    check_locales,
    compare_link_failures,
    repository_markdown_paths,
)


class MarkdownLinkTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temporary_directory.name)
        self.root = self.workspace / "repository"
        self.root.mkdir()

    def tearDown(self):
        self.temporary_directory.cleanup()

    def test_ignores_external_anchors_and_fenced_examples(self):
        page = self.root / "README.md"
        page.write_text(
            "[ok](docs/ok.md)\n[web](https://example.com)\n[anchor](#start)\n"
            "```md\n[example](missing.md)\n```\n",
            encoding="utf-8",
        )
        (self.root / "docs").mkdir()
        (self.root / "docs/ok.md").write_text("ok", encoding="utf-8")
        self.assertEqual([], find_broken_links(self.root, [page]))

    def test_reports_missing_relative_target_with_stable_format(self):
        page = self.root / "README.md"
        page.write_text("[missing](docs/nope.md)\n", encoding="utf-8")
        self.assertEqual(
            ["README.md:1 -> docs/nope.md"],
            find_broken_links(self.root, [page]),
        )

    def test_decodes_targets_and_strips_queries_fragments_and_titles(self):
        page = self.root / "README.md"
        page.write_text(
            '[guide](docs/with%20space.md?view=raw#start "Guide")\n',
            encoding="utf-8",
        )
        (self.root / "docs").mkdir()
        (self.root / "docs/with space.md").write_text("guide", encoding="utf-8")
        self.assertEqual(
            [(1, "docs/with space.md")],
            extract_local_links(page),
        )
        self.assertEqual([], find_broken_links(self.root, [page]))

    def test_does_not_follow_targets_outside_repository(self):
        page = self.root / "README.md"
        page.write_text("[outside](../outside.md)\n", encoding="utf-8")
        (self.workspace / "outside.md").write_text("outside", encoding="utf-8")
        self.assertEqual(
            ["README.md:1 -> ../outside.md"],
            find_broken_links(self.root, [page]),
        )

    def test_baseline_allows_resolved_records_but_rejects_new_records(self):
        resolved = "README.md:1 -> fixed.md"
        new = "README.md:2 -> new.md"
        self.assertEqual(
            ([], [resolved]),
            compare_link_failures([], [resolved]),
        )
        self.assertEqual(
            ([new], [resolved]),
            compare_link_failures([new], [resolved]),
        )

    def test_link_baseline_cannot_be_extended_with_a_new_failure(self):
        record = "README.md:1 -> missing.md"
        (self.root / "README.md").write_text(
            "[missing](missing.md)\n",
            encoding="utf-8",
        )
        content = self.root / "content"
        content.mkdir()
        (content / "known-broken-links.txt").write_text(
            record + "\n",
            encoding="utf-8",
        )
        with redirect_stdout(io.StringIO()):
            self.assertFalse(check_links(self.root))

    def test_localized_check_rejects_makefiles(self):
        for relative in REQUIRED_LOCALIZED:
            for language in ("fr", "en"):
                path = self.root / language / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("placeholder\n", encoding="utf-8")
        (self.root / "fr" / "Makefile").write_text(
            "all:\n\t@true\n",
            encoding="utf-8",
        )

        with redirect_stdout(io.StringIO()):
            self.assertFalse(check_locales(self.root))

    def test_repository_scan_ignores_hidden_directories(self):
        readme = self.root / "README.md"
        readme.write_text("visible\n", encoding="utf-8")
        hidden = self.root / ".private" / "notes.md"
        hidden.parent.mkdir()
        hidden.write_text("internal\n", encoding="utf-8")

        self.assertEqual([readme], repository_markdown_paths(self.root))


if __name__ == "__main__":
    unittest.main()
