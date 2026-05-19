# Changelog

All notable changes to this project are documented here.
Format follows [Conventional Commits](https://www.conventionalcommits.org).

---

## [0.1.6] — 2026-05-19

### Fixed

- **Honey key generation now cumulative per write** — `prepareHoneyKeys` in all four adapters (`localStorage`, `sessionStorage`, `cookie`, `indexedDB`) was computing `needed = config.honeyKeys.count - existingHoneyCount`. After the first write filled the pool, `needed` became `0` for every subsequent write and no new decoys were ever planted. Fixed to always generate `config.honeyKeys.count` fresh honey keys on every write, matching the documented behaviour: N writes with `count: 3` produce N real keys and N × 3 honey keys. The `maxPerBackend` FIFO-eviction cap continues to bound memory in long-lived sessions.

---

## [0.1.5] — 2026-05-18

### Added

- **`vault.signChallenge(challenge, expiresAt)`** — HMAC-SHA256 proof-of-unlock for server-side challenge-response. Signs `challenge ‖ expiresAt_u64_le`; throws `LOCKOUT` if the challenge window has expired and `LOCKED` if the vault is not open. Allows servers to verify that the vault was opened within a specific time window without ever seeing the vault key.
- **`vault.renderFingerprint(canvas, position?)`** — Deterministic visual trust fingerprint on `IEnhancedVault`. Derives a symmetric 5×5 identicon from `HMAC-SHA256(hmacKey, 'visual-fingerprint')`. The correct passcode always produces the same icon; a wrong passcode or phishing page produces a visually distinct icon without storing anything.
- **`contextBinding`** config option — WebAuthn second-factor gate before key activation. `contextBinding.webauthn: true` requires a platform authenticator (TouchID / FaceID / Windows Hello). Enrolled automatically on first unlock; asserted on every subsequent unlock. `onMismatch: 'throw' | 'lock' | 'wipe'` controls the failure action (default: `'throw'`). Origin-bound and hardware-backed.
- **`maxUnlockDurationMs`** config option — Absolute vault-open duration ceiling, independent of idle-timeout resets. The vault locks once cumulative open time reaches this limit, regardless of ongoing read/write activity.
- **`honeyKeys.maxPerBackend`** config option (default: `500`) — FIFO eviction cap on the per-backend in-memory honey key `Set`. The oldest entry is evicted before a new decoy is added when the cap is reached, bounding memory use in long-lived sessions with high write volume.
- **`suspicion.persistScore`** config option (default: `false`) — Persists the suspicion score across page reloads as an HMAC-signed `{ score, timestamp }` snapshot in `localStorage`. Loaded and exponential-decay-adjusted on `unlock()`. A page reload no longer silently resets an attacker's accumulated score to zero.
- **`maxValueBytes`** config option — Maximum plaintext value size in bytes. Writes exceeding the limit throw `VALIDATION_ERROR` before encryption. Applied in all four adapters.
- **`onBeforeWrite`** config option — Write-time validation hook `(key: string, value: string) => boolean`. Returning `false` aborts the write and throws `VALIDATION_ERROR`. Receives the developer alias (pre-rotation) and plaintext value. Applied in all four adapters.

### Security

- **Storage prototype proxy** — `installStorageProxy` now patches both the instance `getItem` and `Storage.prototype.getItem`. The prototype-level patch catches `Storage.prototype.getItem.call(localStorage, key)` bypass attempts that the instance patch misses. A module-level registry coordinates multiple concurrent vaults; the prototype is restored when the last vault is cleaned up.
- **PIN pad `toDataURL` / `toBlob` revocation** — `renderPinPad` overrides `canvas.toDataURL → ''` and `canvas.toBlob → no-op` immediately after the initial draw, closing the XSS exfiltration path of screenshotting the canvas to reconstruct the zone map. Both are restored to prototype defaults in the returned cleanup function.
- **`vaultId` input validation** — `resolveConfig()` validates `vaultId` against `/^[a-zA-Z0-9_-]{1,64}$/` before any further processing. Non-conforming values throw immediately with a descriptive error.
- **`lockoutAttempts` clamped to `[3, 20]`** — Values below 3 trivialise brute-force protection; values above 20 give attackers excessive free guesses. Both are silently corrected by `applyFloors()`.
- **`idleTimeout < 1 000 ms` developer warning** — `resolveConfig()` emits `console.warn` when `idleTimeout` is below 1 000 ms. A sub-1 s timeout fires between `await` checkpoints inside adapter methods, causing `getItem` to silently return `null` immediately after `setItem`. Non-throwing — short timeouts remain valid in security-testing environments.
- **`defaults.ttl` / `defaults.maxReads` validation** — `resolveConfig()` throws immediately for `defaults.ttl ≤ 0` or `defaults.maxReads ≤ 0`.
- **Event handler cap** — `TesseraEmitter` now enforces `MAX_HANDLERS_PER_EVENT = 32`. Registrations beyond this limit are silently dropped, preventing event-loop exhaustion from handlers accumulated during a lockdown event.
- **`exportItem` non-optional** — `exportItem` is now a required (non-optional) method on `IStorageAdapter`. All four adapters implement it; callers get a compile-time guarantee instead of a silent `undefined` from the optional-chaining `?.` pattern.

### Fixed

- **`cleanOrphanedSplits` compound-key deletion** — The `_splits` IndexedDB object store uses `keyPath: ['store', 'key']` (compound primary key). The cleanup routine was calling `objectStore.delete(key)` with only the `key` string, which silently no-oped and left orphaned split shares accumulating in IDB across sessions. Fixed to delete using the full compound key `[record.store, record.key]`.

### Internal

- TypeScript strict-mode errors resolved: missing event names in `TesseraEventName` union (`csp-warning`, `suspicion-cautious`, `suspicion-guarded`, `suspicion-critical`); `Float64Array` index type under `noUncheckedIndexedAccess`; scoped-vault IDB wrapper signatures
- ESLint errors cleared: hex numeric separators (`0x8000` → `0x80_00`); `prefer-code-point`; empty-brace-spaces; `no-typeof-undefined`; missing async IIFE return type
- Branch coverage raised from 88.3 % → 90.76 % (545 tests, all passing); multi-vault and debug-mode test suites added

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
- `reference/threat-model.md` and `reference/limitations.md`
- CI pipeline: type-check → lint → test+coverage (≥ 90%) → build → audit
- `publint` and `are-the-types-wrong` package-quality gates pass
