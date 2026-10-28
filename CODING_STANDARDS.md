# Coding standards

Judgement calls a reviewer checks. Anything a tool can check lives in ruff or mypy instead (`pyproject.toml`).

## Match the surrounding code

New code reads like its neighbours: the same comment density, naming and idiom. Comments say why, in one
line, and stay true. A comment that claims an order ("first", "before") matches the code's order.

## Change the tests with the code

When a refactor moves something, update the tests to the new interface in the same change. Modules carry
only the interface their callers use: properties or setters that exist only so old tests keep working
belong in the tests' update instead.

## One owner per piece of state

- Each log file has one module that writes it and one that reads it back: `AlertLog` for alerts.jsonl,
  `PiholeChanges` for the two Pi-hole change logs.
- One `PiholeChanges` per process, the detector's; other code reaches it through `det.changes`.
- A SETTABLE value is read from the shared `Config` each time it's needed (ADR 0001). Code that stores one
  in `__init__` stops following `/set`.

## Device identity goes through the directory

Naming a device, matching two names (`names.same_name`) and finding a device from what the owner typed
all go through `directory.Directory` and `names`. A new feature that needs a device's name asks there.

## Pi-hole changes are ops

Code that changes Pi-hole builds ops with the builders in `changes.py` and runs them with
`PiholeChanges.apply`, so every change is logged and its Undo is the inverse ops.
