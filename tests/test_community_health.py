from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]

COMMUNITY_FILES = (
    "LICENSE",
    "DISCLAIMER.md",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    "SECURITY.md",
    "SUPPORT.md",
    ".github/ISSUE_TEMPLATE/course-error.yml",
    ".github/ISSUE_TEMPLATE/build-problem.yml",
    ".github/ISSUE_TEMPLATE/content-proposal.yml",
    ".github/ISSUE_TEMPLATE/config.yml",
    ".github/PULL_REQUEST_TEMPLATE.md",
)

ISSUE_FORMS = (
    ".github/ISSUE_TEMPLATE/course-error.yml",
    ".github/ISSUE_TEMPLATE/build-problem.yml",
    ".github/ISSUE_TEMPLATE/content-proposal.yml",
)

COMMON_REQUIRED_FIELDS = (
    "language",
    "affected-path",
    "environment",
    "expected-result",
    "actual-result",
    "authorization-confirmation",
    "code-of-conduct",
)

FORM_SPECIFIC_FIELDS = {
    ".github/ISSUE_TEMPLATE/course-error.yml": ("disputed-explanation",),
    ".github/ISSUE_TEMPLATE/build-problem.yml": ("compiler", "full-diagnostics"),
    ".github/ISSUE_TEMPLATE/content-proposal.yml": (
        "audience",
        "learning-outcome",
        "safety-boundary",
        "fr-en-plan",
    ),
}

LANDING_LINKS = (
    "LICENSE",
    "DISCLAIMER.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "SUPPORT.md",
)

PR_CONTRIBUTING_URL = (
    "https://github.com/Roadmvn/C-Full-Offensive-Course/blob/HEAD/CONTRIBUTING.md"
)


def read(relative):
    path = ROOT / relative
    return path.read_text(encoding="utf-8") if path.is_file() else ""


def form_item(text, field_id):
    for item in re.split(r"(?m)(?=^  - type: )", text):
        if re.search(rf"(?m)^    id: {re.escape(field_id)}$", item):
            return item
    return ""


class CommunityHealthTests(unittest.TestCase):
    def test_required_community_files_exist(self):
        for relative in COMMUNITY_FILES:
            with self.subTest(relative=relative):
                self.assertTrue((ROOT / relative).is_file(), f"missing {relative}")

    def test_license_is_only_the_canonical_mit_text(self):
        license_text = read("LICENSE")

        self.assertTrue(license_text.startswith("MIT License"))
        self.assertIn("Permission is hereby granted", license_text)
        self.assertNotIn("DISCLAIMER", license_text)

    def test_legacy_licence_path_matches_the_canonical_mit_license(self):
        self.assertEqual(
            (ROOT / "LICENSE").read_bytes(),
            (ROOT / "LICENCE").read_bytes(),
        )
        self.assertNotIn("DISCLAIMER", read("LICENCE"))

    def test_disclaimer_preserves_french_warning_and_adds_english_equivalent(self):
        disclaimer = read("DISCLAIMER.md")

        self.assertIn("Ce cours et les techniques présentées", disclaimer)
        self.assertIn("sans autorisation", disclaimer)
        self.assertIn("Toute autre utilisation est de votre seule responsabilité.", disclaimer)
        self.assertIn("Educational use only", disclaimer)
        self.assertIn("Utilisation éducative uniquement", disclaimer)
        self.assertIn("fr/safety/lab-safety.md", disclaimer)
        self.assertIn("en/safety/lab-safety.md", disclaimer)

    def test_root_community_guides_are_bilingual_and_link_both_portals(self):
        for relative in (
            "CONTRIBUTING.md",
            "CODE_OF_CONDUCT.md",
            "SECURITY.md",
            "SUPPORT.md",
        ):
            with self.subTest(relative=relative):
                text = read(relative)
                self.assertRegex(text, r"(?m)^## Français$")
                self.assertRegex(text, r"(?m)^## English$")
                self.assertIn("fr/README.md", text)
                self.assertIn("en/README.md", text)

    def test_contribution_rules_cover_parity_shared_code_status_and_safety(self):
        text = read("CONTRIBUTING.md")
        for marker in (
            "FR/EN parity",
            "shared C code",
            "maturity status",
            "safety review",
            "no new broken links",
            "focused commit",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, text)

    def test_support_and_security_routes_are_separated(self):
        support = read("SUPPORT.md")
        security = read("SECURITY.md")

        self.assertIn("/discussions", support)
        self.assertIn("issue forms", support)
        self.assertIn("/security/advisories/new", support)
        self.assertIn("private GitHub Security Advisory", security)
        self.assertIn("/security/advisories/new", security)
        self.assertIn("Do not publish exploit details", security)
        self.assertIn("operational misuse", security)
        self.assertNotRegex(security, r"\b\d+\s+(?:hour|hours|day|days)\b")

    def test_code_of_conduct_routes_enforcement_to_maintainer(self):
        text = read("CODE_OF_CONDUCT.md")
        self.assertIn("@Roadmvn", text)
        self.assertIn("Welcoming behavior", text)
        self.assertIn("Unacceptable behavior", text)
        self.assertIn("Scope", text)
        self.assertNotRegex(text, r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}")

    def test_issue_forms_have_required_metadata_and_confirmations(self):
        for relative in ISSUE_FORMS:
            with self.subTest(relative=relative):
                text = read(relative)
                self.assertRegex(text, r"(?m)^name:")
                self.assertRegex(text, r"(?m)^description:")
                self.assertRegex(text, r"(?m)^body:")

                for field_id in COMMON_REQUIRED_FIELDS + FORM_SPECIFIC_FIELDS[relative]:
                    item = form_item(text, field_id)
                    self.assertTrue(item, f"{relative} missing required field {field_id}")
                    self.assertRegex(
                        item,
                        r"(?m)^    validations:\n      required: true$",
                        f"{relative} field {field_id} is not required",
                    )

                for confirmation in (
                    "authorization-confirmation",
                    "code-of-conduct",
                ):
                    self.assertRegex(form_item(text, confirmation), r"(?m)^  - type: checkboxes$")

    def test_issue_template_configuration_disables_blanks_and_routes_requests(self):
        text = read(".github/ISSUE_TEMPLATE/config.yml")
        self.assertRegex(text, r"(?m)^blank_issues_enabled: false$")
        self.assertIn("/discussions", text)
        self.assertIn("/security/advisories/new", text)

    def test_pull_request_template_requires_repository_invariants(self):
        text = read(".github/PULL_REQUEST_TEMPLATE.md")
        for marker in (
            "scope",
            "paths changed",
            "FR/EN parity",
            "shared code",
            "tests run",
            "safety review",
            "maturity status",
            "no new broken links",
            "historical paths",
        ):
            with self.subTest(marker=marker):
                self.assertRegex(text, rf"(?im)^- \[ \].*{re.escape(marker)}")

    def test_pull_request_template_uses_pr_context_safe_repository_links(self):
        text = read(".github/PULL_REQUEST_TEMPLATE.md")
        targets = re.findall(r"\[[^]]+\]\(([^)]+)\)", text)
        unsafe_relative_targets = [
            target
            for target in targets
            if not target.startswith(("https://", "http://", "#"))
        ]

        self.assertIn(PR_CONTRIBUTING_URL, targets)
        self.assertEqual([], unsafe_relative_targets)

    def test_landing_pages_link_canonical_community_files(self):
        for landing, prefix in (("README.md", ""), ("fr/README.md", "../"), ("en/README.md", "../")):
            text = read(landing)
            for target in LANDING_LINKS:
                with self.subTest(landing=landing, target=target):
                    self.assertIn(f"]({prefix}{target})", text)


if __name__ == "__main__":
    unittest.main()
