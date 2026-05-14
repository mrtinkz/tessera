# tessera — Browser Storage Encryption Library

## Stack
- **Runtime**: Browser only (Web Crypto API), zero npm dependencies
- **Build**: tsup (ESM + CJS + IIFE + .d.ts generation)
- **Test**: Vitest + happy-dom + fake-indexeddb
- **Lint**: ESLint with @typescript-eslint, unicorn, security, import
- **TypeScript**: Strict mode, es2020 target, exactOptionalPropertyTypes: true

## Architecture
- `src/core/crypto.ts` — PBKDF2-SHA-256 + AES-256-GCM. Stored format: `salt(16)‖iv(12)‖ct‖tag(16)`
- `src/core/session.ts` — `KeySession` class: per-unlock instance, idle-timeout auto-lock, BroadcastChannel cross-tab sync
- `src/core/lockout.ts` — exponential backoff, wipe/delay/throw actions
- `src/adapters/` — `local-storage.ts`, `session-storage.ts`, `cookie.ts`, `indexed-db.ts`
- `src/ui/pin-pad.ts` — Canvas-based PIN pad (digit zones in closure, never in DOM)
- `src/framework/` — React, Vue, Svelte, Angular adapters
- `src/tessera.ts` — Public API: `Tessera.unlock()` object literal
- Tests mirror src structure under `tests/`

## Key Conventions
- `Tessera.unlock()` creates a **new `KeySession` instance** per call — the derived key
  lives only in that closure. No module-level key variable.
- Vault salt is persisted in `localStorage` as `tessera_vault_salt` so the same passcode
  re-derives the same key across sessions.
- All adapters receive their `KeySession` via constructor injection.
- Adapter reads use `session.getKeySafe()` (returns null when locked).
- Adapter writes use `session.getKey()` (throws `LOCKED` when locked).
- All adapters use `encryptWithSalt` / `decryptFull` — never bare `encrypt` / `decrypt`.
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
- fake-indexeddb: import `'fake-indexeddb/auto'` at top of IndexedDB tests.
- Canvas tests: mock `getContext` on the canvas element; keep mock alive across draw() calls.

## Coding Standards
- Explicit return types on public functions.
- No `any` types — use `unknown` and narrow with type guards.
- Passcode: 6–8 characters (PIN pad is digit-only; direct API accepts alphanumeric).
- PBKDF2: ≥ 310,000 iterations (OWASP 2024 minimum).
- `for...of` over `.forEach()` and C-style for loops.
- `addEventListener('error', ...)` over `.onerror` assignment.
