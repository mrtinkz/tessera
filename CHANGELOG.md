# Changelog

All notable changes to this project are documented here.
Format follows [Conventional Commits](https://www.conventionalcommits.org).

---

## [0.1.4] — 2026-05-16

### Fixed

- **Honey key post-wipe write race** — deferred honey writes (scheduled with a 50–2000 ms random delay to resist timing analysis) could race a lockdown: if the async AES-GCM operation completed after `wipeAll` had already cleared the honey manager registry, the write proceeded and re-added the decoy entry to storage. Fixed by re-checking `honeyManager.isHoney()` after the crypto await; the write is discarded if the registry was cleared. Applies to `localStorage`, `sessionStorage`, and cookie adapters.
- **Enhancement demo** — `_simulateHoneyHit` silently returned early because `config.debug` was not set. The demo now passes `debug: true` at unlock time so the honey-key simulation button works correctly.

### Internal

- Branch coverage raised from 89.56 % → 90.18 % (438 tests, all passing)
- `switch-case-braces` lint violation corrected in `honey.ts`

---

## [0.1.0] — 2026-05-14

### Added

- `Tessera.unlock(passcode, config?)` — PBKDF2-SHA-256 + AES-256-GCM vault API
- Four storage adapters: `localStorage`, `sessionStorage`, `cookie`, `IndexedDB`
- Stored format: `salt(16) ‖ iv(12) ‖ ciphertext ‖ auth-tag(16)` per value
- Per-unlock isolated `KeySession` — derived key never held in a module variable
- Idle-timeout auto-lock with `BroadcastChannel` cross-tab synchronisation
- Brute-force lockout: `'delay'` (exponential backoff), `'throw'`, `'wipe'`
- Canvas-based PIN pad (`renderPinPad`) — digit zones in closure, not DOM
- Hold-to-reveal toggle with `aria-pressed` management
- React `useTessera` hook, Vue `useTessera` composable, Svelte `tesseraStore`,
  Angular `TesseraService` + `TesseraModule`
- SSR guard: throws `UNSUPPORTED_ENV` when `crypto.subtle` is unavailable
- OWASP 2024 minimum: ≥ 310 000 PBKDF2 iterations
- Full JSDoc with `@param`, `@returns`, `@throws`, `@security`, `@example`
- `docs/threat-model.md` and `docs/limitations.md`
- CI pipeline: type-check → lint → test+coverage (≥ 90%) → build → audit
- `publint` and `are-the-types-wrong` package-quality gates pass
