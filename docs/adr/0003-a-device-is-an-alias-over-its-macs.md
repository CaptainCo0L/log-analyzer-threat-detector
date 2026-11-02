# 3. A device is an alias over its MACs

Date: 2026-11-02 · Status: accepted

## Context

A Device is the physical thing, which may use several MACs over time (`GLOSSARY.md`). Baselines, mutes,
dedup and rule windows were keyed on one MAC, so a phone on a new private MAC restarted its learning
period, lost its mutes, raised a false `device_silent` from the MAC it left and counted twice towards
shared apexes.

The alternative was to copy each kind of state to the new MAC at every rotation. That needs one migration
per kind of state, misses the in-memory rule windows, and every new per-device feature would have to
remember to join in.

## Decision

`device_alias` maps a MAC to the device's identity, which is the first MAC it was known by. `identify` reads
it, so everything keyed on `ident` follows without knowing about rotation. Pi-hole's groups list real MACs,
so `iot_off_baseline` checks the query's `origin`, not its `ident`.

A link is only made when a private MAC answers over mDNS/Bonjour with a name saved for another MAC: the rule
that already lowers `new_device` and drives rotation sync. It applies with `ROTATION_SYNC` off too, because
it changes nothing in Pi-hole. Rows already recorded under the new MAC are merged into the device, since
Pi-hole only lists a device after its first query and discovery can find one days later.

## Consequences

- Any device can claim any name over mDNS, so a spoofer can inherit a baseline and its mutes. That costs
  less than it looks: a fresh MAC used to get a week with no `beaconing` or `iot_off_baseline` at all, and
  now an apex the real device never used is NEW straight away. Alerts are still logged; a mute only stops
  the push.
- Two devices that give the same mDNS name become one device. On 2026-11-02 the only name shared by several
  live MACs was the iPad's.
- A merge is not undone. `clients-undo` and the Undo button remove the link, but rows already merged stay
  with the device, and the next discovery links the MAC again if it still answers with that name.
- A mute set on a MAC that later merges into another device is lost; they last 7 days at most.
- MACs that rotated before this existed are linked when they next answer, normally the Monday discovery.
  No migration was written.
