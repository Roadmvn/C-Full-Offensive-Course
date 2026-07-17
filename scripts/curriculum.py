#!/usr/bin/env python3

import argparse
from dataclasses import dataclass
import json
from pathlib import Path


SECTION_PREFIXES = tuple(f"{number:02d}-" for number in range(11))
VALID_STATUSES = ("draft", "reference", "ready")


@dataclass(frozen=True)
class CurriculumUnit:
    unit_id: str
    section: str
    course: str
    example: str
    exercise: str
    solutions: tuple[str, ...]
    status: str

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.unit_id,
            "section": self.section,
            "course": self.course,
            "example": self.example,
            "exercise": self.exercise,
            "solutions": list(self.solutions),
            "status": self.status,
        }


def discover_units(root: Path, overrides: dict[str, str]) -> list[CurriculumUnit]:
    root = root.resolve()

    invalid_statuses = sorted(
        {status for status in overrides.values() if status not in VALID_STATUSES},
        key=str,
    )
    if invalid_statuses:
        raise ValueError(f"Unknown curriculum status values: {invalid_statuses}")

    course_paths = sorted(
        (
            path.relative_to(root)
            for path in root.rglob("Cours.md")
            if path.relative_to(root).parts
            and path.relative_to(root).parts[0].startswith(SECTION_PREFIXES)
        ),
        key=lambda path: path.as_posix(),
    )

    units: list[CurriculumUnit] = []
    for course in course_paths:
        directory = course.parent
        example = directory / "example.c"
        exercise = directory / "exercice.md"

        for required_path in (example, exercise):
            if not (root / required_path).is_file():
                raise FileNotFoundError(
                    f"Required curriculum file is missing: {required_path.as_posix()}"
                )

        solution_candidates = (
            directory / "solution.md",
            directory / "solution.c",
        )
        solutions = tuple(
            path.as_posix()
            for path in solution_candidates
            if (root / path).is_file()
        )
        unit_id = directory.as_posix()
        units.append(
            CurriculumUnit(
                unit_id=unit_id,
                section=course.parts[0],
                course=course.as_posix(),
                example=example.as_posix(),
                exercise=exercise.as_posix(),
                solutions=solutions,
                status=overrides.get(unit_id, "draft"),
            )
        )

    unit_ids = {unit.unit_id for unit in units}
    unknown_ids = sorted(set(overrides) - unit_ids)
    if unknown_ids:
        raise ValueError(f"Unknown curriculum unit IDs: {unknown_ids}")

    return units


def write_manifest(root: Path, destination: Path, overrides_path: Path) -> None:
    overrides_payload = json.loads(overrides_path.read_text(encoding="utf-8"))
    if not isinstance(overrides_payload, dict):
        raise ValueError("Status overrides must be a JSON object")

    units = discover_units(root, overrides_payload)
    status_counts = {
        status: sum(unit.status == status for unit in units)
        for status in VALID_STATUSES
    }
    manifest = {
        "schema_version": 1,
        "generated_from": "Cours.md files under sections 00- through 10-",
        "unit_count": len(units),
        "status_counts": status_counts,
        "units": [unit.to_dict() for unit in units],
    }

    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate the curriculum inventory")
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--overrides", type=Path, required=True)
    arguments = parser.parse_args()

    write_manifest(arguments.root, arguments.output, arguments.overrides)
    payload = json.loads(arguments.output.read_text(encoding="utf-8"))
    print(f"Wrote {payload['unit_count']} units to {arguments.output.as_posix()}")


if __name__ == "__main__":
    main()
