# Changelog

All notable changes to this project are documented here.
Format follows [Conventional Commits](https://www.conventionalcommits.org).

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
