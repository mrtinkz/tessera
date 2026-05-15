# tessera — Browser Storage Encryption Library

## Stack

- **Runtime**: Browser only (Web Crypto API), zero npm dependencies
- **Build**: tsup (ESM + CJS + IIFE + .d.ts generation)
- **Test**: Vitest + happy-dom + fake-indexeddb
- **Lint**: ESLint with @typescript-eslint, unicorn, security, import
- **TypeScript**: Strict mode, es2020 target, exactOptionalPropertyTypes: true

## Architecture

- `src/core/crypto.ts` — PBKDF2-SHA-256 + AES-256-GCM. Stored format: `salt(16)‖iv(12)‖ct‖tag(16)`. Also `rotateKeyName` (deterministic AES-GCM with zero IV used as PRF for key-name obfuscation) and `generateHoneyCiphertext`.
- `src/core/session.ts` — `KeySession` class: per-unlock instance, idle-timeout auto-lock, BroadcastChannel cross-tab sync, `reconfirmKey` for half-life access.
- `src/core/lockout.ts` — exponential backoff, wipe/delay/throw actions
- `src/core/config.ts` — `resolveConfig()`: merges developer config with defaults and enforces security floors (lockdown threshold ≥ 10, visibility floor ≥ 200 ms, etc.)
- `src/core/events.ts` — `EventEmitter`: informational-only, fires after tessera has already acted. Handlers cannot cancel or delay security responses.
- `src/core/suspicion.ts` — `SuspicionEngine`: in-memory score, rate-limit detection, visibility-change gating (platform-aware), honey-key tripwires, HMAC-failure recording. Has `destroy()` to remove document listener.
- `src/core/splitter.ts` — XOR-based secret sharing: `splitValue`, `reconstructValue`, base64 helpers.
- `src/core/wipe.ts` — `hardWipe`: overwrites storage slot with 256 bytes of random noise, then removes it. Best-effort forensic mitigation.
- `src/storage/claim.ts` — `generateClaimToken` (returns clean token without prefix), `extractTokenId` (strips `CLAIM_TOKEN_PREFIX` from stored value), `isClaimToken`.
- `src/storage/honey.ts` — `HoneyKeyManager`: tracks per-backend decoy keys in memory only. `generateHoneyKeys` mints new decoys after each real write.
- `src/adapters/` — `local-storage.ts`, `session-storage.ts`, `cookie.ts`, `indexed-db.ts`. All share: key-name rotation via `rotateKeyName`, encrypted metadata block (`writeTime`, `readCount`, TTL, maxReads, half-life), suspicion rate-limiting, honey-key checks on read.
- `src/adapters/session-storage.ts` — additionally supports `mode: 'split'` (XOR secret sharing with IDB) and `mode: 'claim'` (pointer-in-session, value-in-IDB).
- `src/adapters/cookie.ts` — additionally supports `mode: 'claim'`. Cookie names are NOT rotated (cookies travel with HTTP). Hard wipe on `remove()` targets the actual cookie name.
- `src/ui/pin-pad.ts` — Canvas-based PIN pad (digit zones in closure, never in DOM)
- `src/framework/` — React, Vue, Svelte, Angular adapters
- `src/tessera.ts` — Public API: `Tessera.unlock()` object literal returning `IEnhancedVault`
- Tests mirror src structure under `tests/`

## Key Conventions

- `Tessera.unlock()` creates a **new `KeySession` instance** per call — the derived key
  lives only in that closure. No module-level key variable.
- Vault salt is persisted in `localStorage` as `tessera_vault_salt` so the same passcode
  re-derives the same key across sessions.
- All adapters receive their `KeySession`, `EventEmitter`, and `SuspicionEngine` via constructor injection.
- Adapter reads use `session.getKeySafe()` (returns null when locked).
- Adapter writes use `session.getKey()` (throws `LOCKED` when locked).
- All adapters use `encryptWithSalt` / `decryptFull` — never bare `encrypt` / `decrypt`.
- Stored value format: `encryptedMeta.encryptedValue` where meta contains `writeTime`, `readCount`, TTL, maxReads, and half-life thresholds.
- All developer-supplied key names are obfuscated via `rotateKeyName` before hitting storage (except cookie names, which travel with HTTP).
- Claim token format: adapters store `ref:<token>` in the fast backend; the actual value lives encrypted in IDB under the token key. `generateClaimToken()` returns a clean token (no prefix) — adapters prepend `CLAIM_TOKEN_PREFIX` themselves.
- Configuration is resolved once at `unlock` time via `resolveConfig()` and locked for the session. No mid-session reconfiguration.
- `Tessera` is an object literal (not a class) — `unicorn/no-static-only-class`.
- IIFE global is `TesseraLib`; destructure: `const { Tessera, renderPinPad } = TesseraLib`.

## PIN Pad Security Model

- Digits are **always visible** — security comes from position randomisation, not concealment.
- Digit positions re-shuffle after each completed entry (when `randomize: true`).
- Zone map (coordinate → digit) lives only in the `renderPinPad` closure, never the DOM.
- `renderPinPad` returns a cleanup function — call it on component unmount.
- Canvas CSS custom properties must be resolved via `getComputedStyle` before passing
  to `ctx.fillStyle` — Canvas 2D does not resolve `var(--x)` natively.

## Testing

- Each adapter test creates a local `new KeySession()` — never uses a shared singleton.
- `localStorage.clear()` + `resetLockout()` in `beforeEach`; `session.reset()` in `afterEach`.
- Adapter tests construct adapters with `resolveConfig()` and `new EventEmitter()`.
- fake-indexeddb: import `'fake-indexeddb/auto'` at top of IndexedDB tests.
- Canvas tests: mock `getContext` on the canvas element; keep mock alive across draw() calls.

## Coding Standards

- Explicit return types on public functions.
- No `any` types — use `unknown` and narrow with type guards.
- Passcode: 6–8 characters (PIN pad is digit-only; direct API accepts alphanumeric).
- PBKDF2: ≥ 310,000 iterations (OWASP 2024 minimum).
- `for...of` over `.forEach()` and C-style for loops.
- `addEventListener('error', ...)` over `.onerror` assignment.
