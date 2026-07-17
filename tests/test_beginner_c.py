import os
from pathlib import Path
import re
import shutil
import subprocess
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
BEGINNER_ROOT = ROOT / "01-c-fundamentals"
FORBIDDEN_ONBOARDING_FILES = (
    "setup.ps1",
    "build.bat",
    "quiz-runner.py",
    "quiz.json",
)
DIRECT_LESSONS = tuple(
    BEGINNER_ROOT / "lessons" / name
    for name in (
        "01-hello-world.c",
        "02-variables.c",
        "03-if-else.c",
        "04-loops.c",
        "05-functions.c",
    )
)
NON_EXECUTABLE_C = re.compile(
    r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
    re.DOTALL,
)


def executable_c_text(source: Path) -> str:
    return NON_EXECUTABLE_C.sub("", source.read_text(encoding="utf-8"))


def compiler_command(source: Path) -> list[str] | None:
    if os.name == "nt":
        compiler = shutil.which("cl")
        if compiler is None:
            return None
        return [compiler, "/nologo", "/W4", "/Zs", str(source)]

    for compiler_name in ("clang", "gcc"):
        compiler = shutil.which(compiler_name)
        if compiler is not None:
            sequencing_error = (
                "-Werror=unsequenced"
                if compiler_name == "clang"
                else "-Werror=sequence-point"
            )
            return [
                compiler,
                "-std=c11",
                "-Wall",
                "-Wextra",
                sequencing_error,
                "-fsyntax-only",
                str(source),
            ]
    return None


class BeginnerCCompilerTests(unittest.TestCase):
    def test_clang_escalates_unsequenced_warnings(self):
        def find_compiler(name):
            return "/toolchain/clang" if name == "clang" else None

        with (
            patch.object(os, "name", "posix"),
            patch.object(shutil, "which", side_effect=find_compiler),
        ):
            command = compiler_command(Path("lesson.c"))

        self.assertIn("-Werror=unsequenced", command)

    def test_gcc_escalates_sequence_point_warnings(self):
        def find_compiler(name):
            return "/toolchain/gcc" if name == "gcc" else None

        with (
            patch.object(os, "name", "posix"),
            patch.object(shutil, "which", side_effect=find_compiler),
        ):
            command = compiler_command(Path("lesson.c"))

        self.assertIn("-Werror=sequence-point", command)

    def test_all_beginner_examples_and_lessons_compile(self):
        topic_examples = tuple(sorted((BEGINNER_ROOT / "topics").rglob("example.c")))
        sources = topic_examples + DIRECT_LESSONS
        command = compiler_command(sources[0])
        if command is None:
            self.skipTest("no supported C compiler found")

        for source in sources:
            with self.subTest(source=source.relative_to(ROOT)):
                command = compiler_command(source)
                completed = subprocess.run(
                    command,
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(
                    0,
                    completed.returncode,
                    f"{source.relative_to(ROOT)} failed syntax validation\n"
                    f"stdout:\n{completed.stdout}\n"
                    f"stderr:\n{completed.stderr}",
                )


class BeginnerCSourceRegressionTests(unittest.TestCase):
    def test_unsafe_sequencing_forms_do_not_return(self):
        operator_source = executable_c_text(
            BEGINNER_ROOT / "topics/03-Operateurs/example.c"
        )
        function_source = executable_c_text(
            BEGINNER_ROOT / "topics/06-Fonctions/example.c"
        )
        regressions = (
            (
                "pre-increment and x read in one printf",
                operator_source,
                r"\bprintf\s*\([^;]*\+\+\s*x\s*,\s*x\s*\)\s*;",
            ),
            (
                "post-increment and x read in one printf",
                operator_source,
                r"\bprintf\s*\([^;]*x\s*\+\+\s*,\s*x\s*\)\s*;",
            ),
            (
                "assignment of 5 to x inside printf arguments",
                operator_source,
                r"\bprintf\s*\([^;]*\(\s*x\s*=\s*5\s*\)[^;]*\)\s*;",
            ),
            (
                "executable SQUARE_MACRO(x++)",
                function_source,
                r"\bSQUARE_MACRO\s*\(\s*x\s*\+\+\s*\)",
            ),
        )

        for label, source, pattern in regressions:
            with self.subTest(regression=label):
                match = re.search(pattern, source)
                if match is not None:
                    self.fail(f"{label}: matched executable code {match.group(0)!r}")


class BeginnerDocumentationTests(unittest.TestCase):
    def test_onboarding_only_references_existing_tools(self):
        for relative in ("README.md", "CHECKPOINT.md"):
            path = BEGINNER_ROOT / relative
            text = path.read_text(encoding="utf-8")
            for forbidden in FORBIDDEN_ONBOARDING_FILES:
                with self.subTest(path=path.relative_to(ROOT), forbidden=forbidden):
                    self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
