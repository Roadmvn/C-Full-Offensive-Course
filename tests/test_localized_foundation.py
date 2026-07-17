import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
GIT_DOWNLOADS = "https://git-scm.com/downloads/"

REQUIRED_LOCALIZED = (
    "start-here.md",
    "paths.md",
    "setup/windows.md",
    "setup/linux.md",
    "setup/macos.md",
    "safety/lab-safety.md",
)

README_NAVIGATION = (
    "start-here.md",
    "paths.md",
    "safety/lab-safety.md",
)

CORE_MODULES = (
    "00-prerequisites",
    "01-c-fundamentals",
    "02-memory-pointers",
    "03-asm-x64",
    "04-windows-fundamentals",
    "05-windows-advanced",
    "06-network",
    "07-beacon-dev",
)

PATH_HEADINGS = {
    "fr": (
        "## 1. Tronc commun débutant en 12 semaines",
        "## 2. Approfondissement Windows",
        "## 3. Spécialisation Linux ou macOS",
        "## 4. Références avancées",
    ),
    "en": (
        "## 1. 12-week beginner core",
        "## 2. Windows depth",
        "## 3. Linux or macOS specialization",
        "## 4. Advanced reference",
    ),
}

SAFETY_MARKERS = {
    "fr": (
        "Autorisation écrite",
        "Cible possédée",
        "VM jetable",
        "Instantané",
        "host-only",
        "loopback",
        "Aucun secret réel",
        "Aucune donnée professionnelle ou personnelle",
        "Privilèges documentés",
        "Conditions d'arrêt",
        "Plan de nettoyage",
        "Réponse à incident",
        "exposition publique",
        "persistance",
        "collecte d'identifiants",
        "hors du labo isolé",
    ),
    "en": (
        "Written authorization",
        "Owned target",
        "Disposable VM",
        "Snapshot",
        "host-only",
        "loopback",
        "No real secrets",
        "No corporate or personal data",
        "Documented privileges",
        "Stop conditions",
        "Cleanup plan",
        "Incident response",
        "Public exposure",
        "persistence",
        "credential collection",
        "outside the isolated lab",
    ),
}

FENCED_BLOCK_PATTERN = re.compile(
    r"^```(?P<info>[^\n]*)\n(?P<body>.*?)^```[ \t]*$",
    re.MULTILINE | re.DOTALL,
)
MARKDOWN_LINK_PATTERN = re.compile(
    r"!?\[[^\]]*\]\(\s*(?:<(?P<angle>[^>]+)>|(?P<bare>[^\s)]+))"
)
INLINE_CODE_PATTERN = re.compile(r"(?<!`)`([^`\n]+)`(?!`)")


def read_page(language, relative):
    return (ROOT / language / relative).read_text(encoding="utf-8")


def markdown_targets(text):
    prose = FENCED_BLOCK_PATTERN.sub("", text)
    return tuple(
        match.group("angle") or match.group("bare")
        for match in MARKDOWN_LINK_PATTERN.finditer(prose)
    )


def normalized_fenced_blocks(text):
    blocks = []
    for match in FENCED_BLOCK_PATTERN.finditer(text):
        body = "\n".join(line.rstrip() for line in match.group("body").strip().splitlines())
        blocks.append((match.group("info").strip(), body))
    return tuple(blocks)


def inline_code_identifiers(text):
    prose = FENCED_BLOCK_PATTERN.sub("", text)
    return tuple(sorted(match.group(1).strip() for match in INLINE_CODE_PATTERN.finditer(prose)))


class LocalizedFoundationTests(unittest.TestCase):
    def test_root_routes_to_both_languages(self):
        text = (ROOT / "README.md").read_text(encoding="utf-8")
        targets = markdown_targets(text)
        self.assertIn("fr/README.md", targets)
        self.assertIn("en/README.md", targets)

    def test_language_homes_use_markdown_navigation(self):
        for language, other in (("fr", "en"), ("en", "fr")):
            with self.subTest(language=language):
                targets = markdown_targets(read_page(language, "README.md"))
                self.assertIn(f"../{other}/README.md", targets)
                for target in README_NAVIGATION:
                    self.assertIn(target, targets)

    def test_roadmap_ambitions_are_qualified_in_both_languages(self):
        french = (ROOT / "fr/README.md").read_text(encoding="utf-8")
        english = (ROOT / "en/README.md").read_text(encoding="utf-8")
        self.assertNotIn(
            "Du printf() au beacon C2 fonctionnel en 12 semaines.",
            french,
        )
        self.assertNotIn(
            "jusqu'a la capacite d'ecrire des outils offensifs de niveau professionnel.",
            french,
        )
        self.assertIn("objectif historique et aspirationnel", french)
        self.assertIn("pas un résultat garanti", french)
        self.assertIn("historical, aspirational roadmap", english)
        self.assertIn("not a guaranteed outcome", english)
        self.assertIn("`Draft`", french)
        self.assertIn("`Draft`", english)

    def test_localized_trees_never_copy_code(self):
        forbidden = {".c", ".h", ".exe", ".dll", ".so", ".dylib", ".a", ".lib"}
        copied = [p for base in (ROOT / "fr", ROOT / "en") for p in base.rglob("*") if p.is_file() and p.suffix.lower() in forbidden]
        self.assertEqual([], copied)

    def test_required_localized_pages_are_symmetric(self):
        for relative in REQUIRED_LOCALIZED:
            depth = len(Path(relative).parts)
            for language, other in (("fr", "en"), ("en", "fr")):
                path = ROOT / language / relative
                with self.subTest(relative=relative, language=language):
                    self.assertTrue(path.is_file(), f"missing {path.relative_to(ROOT)}")
                    switch = f"{'../' * depth}{other}/{relative}"
                    self.assertIn(switch, markdown_targets(path.read_text(encoding="utf-8")))

    def test_required_localized_pages_keep_commands_and_identifiers_in_parity(self):
        for relative in REQUIRED_LOCALIZED:
            with self.subTest(relative=relative):
                french = read_page("fr", relative)
                english = read_page("en", relative)
                self.assertEqual(
                    normalized_fenced_blocks(french),
                    normalized_fenced_blocks(english),
                )
                self.assertEqual(
                    inline_code_identifiers(french),
                    inline_code_identifiers(english),
                )

    def test_start_pages_reference_shared_hello_world_lesson(self):
        target = "../01-c-fundamentals/lessons/01-hello-world.c"
        for language in ("fr", "en"):
            path = ROOT / language / "start-here.md"
            with self.subTest(language=language):
                self.assertTrue(path.is_file(), f"missing {path.relative_to(ROOT)}")
                self.assertIn(target, path.read_text(encoding="utf-8"))

    def test_start_guides_verify_git_before_clone(self):
        for language in ("fr", "en"):
            with self.subTest(language=language):
                text = read_page(language, "start-here.md")
                self.assertIn("git --version", text)
                self.assertLess(text.index("git --version"), text.index("git clone "))
                self.assertIn(GIT_DOWNLOADS, markdown_targets(text))

    def test_platform_setup_guides_require_and_verify_git(self):
        requirement = {
            "fr": "Git est requis pour cloner le dépôt du cours.",
            "en": "Git is required to clone the course repository.",
        }
        for relative in ("setup/windows.md", "setup/linux.md", "setup/macos.md"):
            for language in ("fr", "en"):
                with self.subTest(relative=relative, language=language):
                    text = read_page(language, relative)
                    self.assertIn(requirement[language], text)
                    self.assertIn("git --version", text)
                    self.assertIn(GIT_DOWNLOADS, markdown_targets(text))

    def test_paths_require_x86_64_for_module_03(self):
        requirement = {
            "fr": "`03-asm-x64` nécessite un environnement `x86-64`",
            "en": "`03-asm-x64` requires an `x86-64` environment",
        }
        for language in ("fr", "en"):
            with self.subTest(language=language):
                self.assertIn(requirement[language], read_page(language, "paths.md"))

    def test_macos_setup_explains_apple_silicon_x86_64_vm(self):
        requirement = {
            "fr": (
                "les exercices d'assembleur de `03-asm-x64` nécessitent une VM `x86-64`",
                "Rosetta seule ne garantit pas",
            ),
            "en": (
                "the `03-asm-x64` assembly exercises require an `x86-64` VM",
                "Rosetta alone does not guarantee",
            ),
        }
        for language in ("fr", "en"):
            with self.subTest(language=language):
                text = read_page(language, "setup/macos.md")
                self.assertIn("Apple Silicon", text)
                for marker in requirement[language]:
                    self.assertIn(marker, text)

    def test_paths_keep_four_paths_and_core_module_order(self):
        for language in ("fr", "en"):
            with self.subTest(language=language):
                text = read_page(language, "paths.md")
                heading_positions = [text.index(heading) for heading in PATH_HEADINGS[language]]
                module_positions = [text.index(f"`{module}`") for module in CORE_MODULES]
                self.assertEqual(sorted(heading_positions), heading_positions)
                self.assertEqual(sorted(module_positions), module_positions)

    def test_lab_safety_gate_covers_core_requirements(self):
        for language in ("fr", "en"):
            with self.subTest(language=language):
                text = read_page(language, "safety/lab-safety.md")
                for marker in SAFETY_MARKERS[language]:
                    self.assertIn(marker, text)

    def test_legacy_methodology_uses_the_same_isolated_network_gate(self):
        methodology = (ROOT / "docs/LEARNING_METHODOLOGY.md").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("NAT ou Host-Only", methodology)
        self.assertIn("Host-Only ou loopback", methodology)

    def test_french_advanced_unit_count_matches_the_manifest(self):
        manifest = json.loads(
            (ROOT / "content/curriculum.json").read_text(encoding="utf-8")
        )
        advanced_count = sum(
            unit["section"] == "10-advanced" for unit in manifest["units"]
        )
        french = read_page("fr", "README.md")
        self.assertRegex(
            french,
            rf"\| `10-advanced` \| {advanced_count} \|",
        )


if __name__ == "__main__":
    unittest.main()
