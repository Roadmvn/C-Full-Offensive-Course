[Français](../fr/paths.md) · **English**

# Choose a learning path

Start with the path that matches your current skills and operating system. The estimates are planning ranges, not completion guarantees. Unit readiness and maturity come from the `status` fields in [`content/curriculum.json`](../content/curriculum.json); check that inventory before relying on an advanced unit.

All hands-on security work is also subject to the [lab-safety gate](safety/lab-safety.md).

## 1. 12-week beginner core

Follow the shared sections in this order: `00-prerequisites`, `01-c-fundamentals`, `02-memory-pointers`, `03-asm-x64`, `04-windows-fundamentals`, `05-windows-advanced`, `06-network`, then `07-beacon-dev`. Section `03-asm-x64` comes before Windows internals so that registers, calling conventions, and memory behavior have already been introduced.

`03-asm-x64` requires an `x86-64` environment for its assembly exercises. On a host with another architecture, prepare an x86-64 VM before starting that module.

- **Prerequisites:** none; complete the reading and written exercises in `00-prerequisites` if the machine model is new to you.
- **Estimated range:** 12 weeks for the proposed core, with extra time for any unit marked `Draft` or any concept that needs repetition.
- **Platforms:** Windows, Linux, or macOS for sections `00` through `02`; an x86-64 environment for `03`; a disposable Windows VM for Windows-specific work in later core sections.
- **Outcome:** a working foundation in C, memory, x64 assembly, Windows concepts, networking, and the structure of an integrated project. This is a learning objective, not a guaranteed professional level.
- **Status source:** use [`content/curriculum.json`](../content/curriculum.json) to distinguish ready units from `Draft` material.

## 2. Windows depth

Study `04-windows-fundamentals`, then `05-windows-advanced`, and consult selected Windows-relevant references in `10-advanced` only when a core unit points to them or your goal requires them.

- **Prerequisites:** complete or demonstrate the knowledge from `01`, `02`, and `03`; pass the lab-safety gate before practical security exercises.
- **Estimated range:** 4 to 8 or more additional weeks, depending on prior Windows and debugging experience and the audited status of selected units.
- **Platforms:** a disposable Windows 10 or Windows 11 VM with a restorable snapshot and a host-only or loopback network.
- **Outcome:** understand and examine Windows APIs, processes, threads, memory, and selected advanced references inside an authorized lab.
- **Status source:** verify every selected `04`, `05`, or `10` unit in [`content/curriculum.json`](../content/curriculum.json); visible does not necessarily mean ready.

## 3. Linux or macOS specialization

After `02-memory-pointers` and `03-asm-x64`, choose either `08-linux` or `09-macos`. You do not need to complete both specializations at the same time.

- **Prerequisites:** C fundamentals plus sections `02` and `03`; pass the lab-safety gate before practical security exercises.
- **Estimated range:** 4 to 8 or more additional weeks for one platform, adjusted to the readiness of its units and your systems background.
- **Platforms:** a disposable Linux VM for `08-linux`, or a dedicated/disposable macOS test environment for `09-macos`; keep its network isolated.
- **Outcome:** relate C, memory, executable formats, system interfaces, and platform protections on the selected operating system.
- **Status source:** check the selected `08` or `09` entries in [`content/curriculum.json`](../content/curriculum.json) and treat `Draft` units as incomplete references.

## 4. Advanced reference

Use `10-advanced` as a topic-indexed reference. It is explicitly outside the 12-week promise and is not the next automatic step for every learner.

- **Prerequisites:** strong C, memory, assembly, operating-system, and debugging foundations, plus any earlier module named by the selected reference.
- **Estimated range:** open-ended; choose one audited topic at a time rather than treating `10` as a fixed-length course.
- **Platforms:** varies by topic and must remain within an owned, authorized, isolated lab.
- **Outcome:** locate and evaluate advanced material without mistaking inventory coverage for completed instruction.
- **Status source:** the selected entry's `status` in [`content/curriculum.json`](../content/curriculum.json) is authoritative; a `Draft` entry is outside the ready curriculum.

## Start

If you have not yet verified a compiler, follow [Start here](start-here.md). Then record your chosen path and the next ready unit you will complete.
