# ActiveGraph inspiration: run events, reducer, fork/diff

Part of a fleet-wide effort inspired by Yohei Nakajima's
[ActiveGraph](https://github.com/yoheinakajima/activegraph). Master notes:
`~/notes/activegraph-credits.md`. ActiveGraph is a reference architecture only;
no code from it is vendored or depended on here.

## What we borrowed

- **State is a projection of an append-only log**, folded by a single reducer.
  ActiveGraph's `apply_event` (`activegraph/core/graph.py`) is the only mutator;
  losing materialized state is recoverable by replay.
- **Fork by copying the log up to a cut point and replaying it**
  (`fork_run`, `activegraph/store/sqlite.py`), then diffing runs structurally
  (`compute_diff`, `activegraph/runtime/diff.py`).

## What landed in hotwash

- A new `run_events` table (`RunEvent`) carrying structured, machine-readable
  payloads, emitted alongside the existing prose `execution_events` at every
  mutation (`create_execution`, `update_step`, `upload_evidence`,
  `update_execution`).
- A pure reducer (`api/services/replay.py`): `build_steps(events)` folds the log
  into step state, mirroring the router's mutation rules exactly.
- `GET /executions/{id}/replay` — the **correctness oracle**: rebuilds step
  state from the log and reports `matches_persisted`. If it is ever false, the
  reducer and the router have drifted.
- `POST /executions/{id}/fork[?at_event_id=N]` — copies run events up to the cut
  into a new execution and replays them to seed its state; the fork diverges
  freely.
- `GET /executions/{id}/diff/{other}` — structural per-node diff of two runs.

The payoff: a run is now replayable and forkable. You can branch a run at a
decision point, take it a different way, and diff the outcomes, and the replay
oracle guarantees the event stream is a faithful record of what happened.

## What we did differently, and why

- **Additive, not canonical.** `steps_json` remains the source of truth for live
  reads; the reducer reproduces it independently so the two can be cross-checked.
  hotwash's old `execution_events` were lossy prose (no payload, no order key),
  so making them canonical would have been a risky rewrite of the one path all
  state flows through. The new stream sits beside the old one.
- **Only one new table; no schema change to `executions`.** hotwash has no
  migration framework (`Base.metadata.create_all` only creates *new* tables, it
  will not ALTER an existing one). So genesis and fork lineage live in event
  payloads (`run_started.genesis`, `run_forked`) rather than new columns. This
  is both migration-safe on existing databases and more ActiveGraph-faithful:
  the log carries everything, and state and lineage are projections of it.
- **Genesis in the log, not the playbook.** ActiveGraph replays from the event
  log alone. We store the initial step list in the `run_started` event so replay
  never depends on the (mutable) playbook graph, which a run does not otherwise
  pin a version of.

## Feedback worth sending Yohei

Two practical notes from porting the pattern onto an existing app: (1) the
biggest adoption cost was not the reducer but guaranteeing it stays in lockstep
with the pre-existing imperative mutation path, so a built-in "projection ==
live state" oracle (which ActiveGraph gets for free because the projection *is*
the state) turned out to be the highest-value single piece to add first. (2)
Putting genesis and lineage inside event payloads instead of table columns made
the whole thing land with zero schema migration, which matters a lot for
retrofits onto tools without a migration framework.
