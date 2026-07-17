[Français](../../fr/safety/lab-safety.md) · **English**

# Lab-safety gate

This gate applies before every hands-on security exercise. Do not start while any item is unchecked. Recheck it when the target, network, snapshot, exercise, or authorization changes.

## Required before execution

- [ ] **Written authorization:** I have a written scope naming the owner, permitted target, permitted exercise, dates, and stop contact.
- [ ] **Owned target:** every target is a lab system I own and control; no third-party, public, corporate, or personal system is included.
- [ ] **Disposable VM:** the exercise runs in a disposable virtual machine or an equivalently disposable dedicated test system, not on a daily-use host.
- [ ] **Snapshot:** I created and verified a restorable snapshot before the exercise.
- [ ] **Isolated network:** the lab uses host-only or loopback networking. Bridged networking, public exposure, inbound port forwarding, and routes to unrelated networks are disabled.
- [ ] **No real secrets:** the lab contains only synthetic test credentials, tokens, certificates, and keys—never real secrets.
- [ ] **No corporate or personal data:** the VM, inputs, outputs, and mounted folders contain no production, employer, customer, or personal data.
- [ ] **Documented privileges:** I recorded the lab accounts, assigned privileges, required elevated actions, and who approved them. I will use the least privilege the exercise needs.
- [ ] **Stop conditions:** I will stop immediately if traffic reaches an unexpected address, isolation changes, the target differs from scope, monitoring is lost, the host becomes unstable, or I am unsure about authorization.
- [ ] **Cleanup plan:** I know which generated processes, files, accounts, logs, and network changes the exercise can create, and I have a plan to terminate or remove them and then restore or delete the VM.
- [ ] **Incident response:** I know how to isolate the VM, preserve relevant evidence, record times and actions, notify the owner or course supervisor, and wait for approval before resuming.

## Scope boundary

Public exposure, persistence, credential collection, and execution outside the isolated lab are out of scope. A lesson that cannot be completed within these limits must be postponed, not adapted to a real target.

Authorization for one target or date does not authorize another. Being able to reach a system is not permission to test it.

## If a stop condition occurs

1. Stop the exercise and do not launch another command from it.
2. Disconnect or pause the lab network without interacting with any unexpected system.
3. Preserve the VM state, relevant logs, the time, and the last known action; do not erase evidence.
4. Notify the named owner or supervisor using the agreed incident channel.
5. Resume only after isolation is confirmed and written authorization is renewed or clarified.

## Normal cleanup

When no incident occurred, stop generated processes, remove synthetic credentials and generated artifacts, undo lab-only network changes, and revert the snapshot or delete the disposable VM. Confirm that no shared folder, mounted device, forwarding rule, or lab account remains active.

If an incident may have occurred, follow the incident-response steps instead of normal cleanup so that evidence is preserved.

[Start here](../start-here.md) · [Choose a path](../paths.md) · [Course home](../README.md)
