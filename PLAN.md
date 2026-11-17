# TardQuest API — 4.1 Plan

Branch: `4.1` (cut from `4.0` @ `ef8a637`)
Scope: **Balanced** — stabilize and harden first, then a small set of high-value
features, plus basic release/CI process.

Current baseline: `4.0.2608`. Public profile = gameplay API
(`start`, `update`, `leaderboard`, `pigeon/*`, `status`, `abuse`); private
profile (separate repo) adds `auth` + deprecated `launcher`.

---

## Track A — Stabilization & fixes (P0)

Goal: close test gaps and fix config/code inconsistencies. Low effort, builds
trust before any feature work.

- **A1. Leaderboard version-gating tests.** The rule (legacy 3.x clients may
  play but `POST /leaderboard` returns `400` with `update_required`; clients
  below `minSupportedClientVersion` are rejected) is untested. Add integration
  tests across three bands: `>= minClientVersion`, between
  `minSupportedClientVersion` and `minClientVersion`, and below
  `minSupportedClientVersion`.
- **A2. Abuse flagging tests.** `abuse.service.js` (IP flagging on auth-fail and
  sanitize/duplicate thresholds, flag expiry) has no tests. Add unit tests for
  threshold crossing and flag-window expiry.
- **A3. `/api` prefix parity.** Confirm every registered route resolves
  identically at `/x` and `/api/x`; add a parity test driven off the registry.
- **A4. Corrupted-date robustness.** `session.service.js` already guards
  `new Date(expires)` in try/catch (issue #9 pattern). Audit session expiry,
  purge, and `last_floor_update`/`last_message_received_at` parsing for the same
  defense so a bad DB row can't crash a request.
- **A5. Reconcile session lifetime.** `sessionTimeoutMinutes = 43200` (30 days)
  but `sessionPurgeAgeDays = 7`: rows are purged ~4× before their `expires`
  value ever takes effect. Decide intended semantics (cap TTL to purge age, or
  align purge to TTL) and fix defaults + docs.
- **A6. Fix `dev:private` script path.** `package.json` runs
  `src/private/entries/private.js`; the public entry is `src/entries/public.js`
  and there is no `private/` subdir in this repo. Verify against the private
  repo and align the path.

---

## Track B — Hardening & anti-cheat (P1)

- **B1. PoW secret binding (intent of closed issue #10).** Confirm the PoW
  challenge issued at `/start` is derived from a **server-held secret**
  (`recoveryCodePepper` / per-session salt), is bound to the `session_id`, and is
  **single-use** (consumed on `update` death-submit / `POST /leaderboard`).
  Add a replay test: the same solved challenge must not validate twice.
- **B2. Cheat-payload integration suite.** Drive `/update` + `/leaderboard`
  with floor-skip, level-jump, insufficient-EXP, and level-up-spam payloads;
  assert VocaGuard rejects each. Complements existing `vocaguard` unit tests.
- **B3. Pigeon message sanitization edge cases.** Extend
  `tests/unit/pigeon.test.js` with Unicode/zero-width, nested HTML entities, and
  protocol-URL variants to lock the sanitizer against bypasses.

---

## Track C — Features (P2, small & deliberate)

- **C1. Shared rate-limit store.** Docs note limits are **in-memory, per
  process** — wrong for multi-instance deploys (echoes closed issue #1). Option:
  add a Redis-backed store for `express-rate-limit`, or explicitly document a
  single-process deployment guarantee. Decide before adding the dependency.
- **C2. Finish launcher-route removal on a cutoff.** Launcher routes already
  return `410` + `Deprecation` header (private profile). Define a client-version
  cutoff and a date; then remove `launcher` from the registry and its tests.
- **C3. Pigeon delivery tuning (verify, not fix).** Repeat-sender penalty
  (`repeatSenderPenalty = 0.5`) and weighted selection are already implemented
  (closed issues #7/#8 resolved). If tuning is wanted, add a test asserting the
  weighting inputs (floor proximity, age, verified multiplier, jitter) before
  changing constants.

---

## Track D — Process & release (P1, but partly blocked)

- **D1. CI on PRs.** No `.github/workflows` exists. Add a workflow that runs
  `npm test` and `npm run build` (public + private where secrets allow).
  **Blocked:** current `gh` token lacks the `workflow` scope — needs a one-line
  re-auth to add it before I can write/commit workflow files.
- **D2. Release tagging for 4.1.** `git tag` is currently empty. Establish a
  tag (e.g. `v4.1.0`) and align `package.json` versioning (currently date-styled
  `4.0.2608`) with a documented scheme.
- **D3. Migration tooling home.** Move `tests/other/migrate-legacy-db.js` (and
  the leaderboard dedup-merge from `bf78ff7`) into a real `scripts/` folder with
  a runner + README. Keep behavior, improve discoverability.

---

## Suggested execution order

1. **A1–A6** (stabilization) — safe, isolated, ships first.
2. **B1–B3** (hardening) — once tests exist, lock down anti-cheat.
3. **D1–D2** (CI + release) — unblocks safe iteration on the rest.
4. **C1–C3** (features) — each behind a small decision/flag.

## Open decisions before coding

- **C1:** Redis dependency vs. documented single-process limit?
- **A5:** session TTL capped to 7-day purge, or purge extended to match TTL?
- **C2:** client version + calendar date for launcher removal cutoff?
- **D2:** keep date-based versioning (`4.0.2608`) or switch to semver for `4.1`?
- **D1:** re-auth `gh` to add the `workflow` scope now, or defer CI?
