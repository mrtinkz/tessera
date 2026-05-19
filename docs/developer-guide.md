# tessera — Developer Guide

This guide is for contributors and anyone who wants to understand the internals,
run the CI pipeline locally, or add new features.

---

## Contents

- [Repository layout](#repository-layout)
- [Prerequisites](#prerequisites)
- [Setup](#setup)
- [Running the CI pipeline locally](#running-the-ci-pipeline-locally)
- [Architecture overview](#architecture-overview)
- [Key invariants](#key-invariants)
- [Adding a new test](#adding-a-new-test)
- [Adding a new adapter](#adding-a-new-adapter)
- [Coding standards](#coding-standards)
- [Release checklist](#release-checklist)

---

## Repository layout

```
src/
  tessera.ts          ← Public API (Tessera.unlock → IEnhancedVault)
  types.ts            ← All shared types and constants
  core/
    crypto.ts         ← PBKDF2 + AES-256-GCM primitives
    session.ts        ← KeySession: per-unlock key lifecycle
    config.ts         ← resolveConfig(): merges + enforces security floors
    events.ts         ← EventEmitter: informational-only, fires after action
    lockout.ts        ← Exponential backoff / wipe / throw
    suspicion.ts      ← SuspicionEngine: score, rate-limit, honey tripwires
    splitter.ts       ← XOR secret sharing (split mode)
    wipe.ts           ← hardWipe: forensic noise overwrite then remove
  adapters/
    local-storage.ts  ← localStorage adapter
    session-storage.ts← sessionStorage adapter (direct / claim / split modes)
    cookie.ts         ← Cookie adapter (direct / claim modes)
    indexed-db.ts     ← IndexedDB adapter
  storage/
    claim.ts          ← Claim token generation and extraction
    honey.ts          ← HoneyKeyManager: in-memory decoy registry
  ui/
    pin-pad.ts        ← Canvas PIN pad (renderPinPad)
    styles.ts         ← CSS custom properties helper
  framework/
    react/index.ts    ← useTessera hook
    vue/index.ts      ← useTessera composable
    svelte/index.ts   ← tesseraStore
    angular/index.ts  ← TesseraService + TesseraModule
docs/
  threat-model.md     ← Threats in scope and out of scope
  limitations.md      ← Honest list of what tessera does not protect
  developer-guide.md  ← This file
tests/                ← Mirrors src/ structure; one test file per source file
```

---

## Prerequisites

- **Node.js** ≥ 20.19.0 or ≥ 22.12.0 (see `engines` in `package.json`)
- **npm** ≥ 10

---

## Setup

```bash
git clone https://github.com/mrtinkz/tessera
cd tessera
npm ci --legacy-peer-deps
```

`--legacy-peer-deps` is required because the Angular peer dependency tree
expects older peer versions; using it here does not affect the published bundle
(Angular is dev-only).

---

## Running the CI pipeline locally

The CI runs five steps in order. Run them the same way:

```bash
# 1. Type-check (no emit)
npm run type-check

# 2. Lint (fails above 25 warnings)
npm run lint

# 3. Tests + branch coverage (threshold: ≥ 90 % lines / branches / functions)
npm run test:coverage

# 4. Build (ESM + CJS + IIFE + .d.ts)
npm run build

# 5. Security audit (fails on HIGH or CRITICAL)
npm audit --audit-level=high
```

All five must pass before a pull request is merged. The `npm run lint` step uses
`--max-warnings 25`; the exact threshold is checked in CI.

To run just the tests without coverage (faster during development):

```bash
npm test
# or watch mode:
npm run test:watch
```

---

## Architecture overview

### One key per unlock call

`Tessera.unlock(passcode, config?)` creates a brand-new `KeySession` on every
call. The derived `CryptoKey` lives only in that session's closure — there is
no module-level key variable. If someone monkey-patches the module after the
fact, they cannot reach a key from a previous unlock.

### Stored value format

Every value written to any backend has the same on-disk format:

```
encryptedMeta . encryptedValue
```

Both parts are individually AES-256-GCM encrypted. `encryptedMeta` contains:
`writeTime`, `readCount`, `ttl`, `maxReads`, `sensitivity`, `onSuspicion`, and
optional `halfLifeSoft` / `halfLifeHard`. `encryptedValue` contains the raw
payload. The `.` separator lets adapters split metadata from value without a
second decrypt call.

### Key-name rotation

Developer-supplied key names (e.g. `'cart'`) are **never written to storage**.
Every adapter derives a storage key via `HMAC-SHA256(hmacKey, developerName)`,
producing `t_` + 32 hex chars. This hides the number and names of stored keys
from any script that enumerates storage directly. The HMAC key is a separate
PBKDF2 derivation from the same passcode.

### Native storage proxy

When the vault is unlocked, `localStorage.getItem` and
`sessionStorage.getItem` are replaced with thin proxies on both the instance
and `Storage.prototype`. Any `getItem` call for a key that matches the honey
registry fires `honey-triggered`, increments the suspicion score, and can
trigger a full lockdown — even if the caller never went through the tessera
API. The proxy is removed on `lock()`, `terminate()`, and lockdown.

### EventEmitter is informational only

Events fire **after** tessera has already acted. A `vault-locked` listener
cannot cancel the lock. This is intentional: security responses must not be
deferrable by application code.

### Adapters are constructor-injected

All adapters receive `config`, `session`, `events`, and optionally `suspicion`
via the constructor. There is no global state. This makes unit tests simple:
create a fresh adapter per test, pass a `new KeySession()`, done.

---

## Key invariants

These must be preserved in any change:

| Invariant                                                    | Where enforced                                    |
| ------------------------------------------------------------ | ------------------------------------------------- |
| `Tessera` is an object literal, not a class                  | `src/tessera.ts` — `unicorn/no-static-only-class` |
| `PBKDF2 iterations ≥ 310 000`                                | `resolveConfig()` enforces a floor                |
| `lockdownThreshold ≥ 10`                                     | `applyFloors()` in `config.ts`                    |
| `visibilityChange.duration.floor ≥ 200 ms`                   | `applyFloors()` in `config.ts`                    |
| `lockoutAttempts` clamped to [3, 20]                         | `applyFloors()` in `config.ts`                    |
| `vaultId` matches `/^[a-zA-Z0-9_-]{1,64}$/`                  | `resolveConfig()` in `config.ts`                  |
| Adapter writes use `session.getKey()` (throws LOCKED)        | All four adapters                                 |
| Adapter reads use `session.getKeySafe()` (returns null)      | All four adapters                                 |
| Honey keys written AFTER real value                          | All adapters — post-write background task         |
| Honey write checks `isHoney()` after the async crypto op     | Prevents post-wipe race                           |
| `cleanOrphanedSplits` deletes by compound key `[store, key]` | `indexed-db.ts`                                   |

---

## Adding a new test

Test files live in `tests/` and mirror `src/`:

```
src/adapters/local-storage.ts  →  tests/adapters/local-storage.test.ts
```

Each test file follows this pattern:

```ts
import { beforeEach, afterEach, describe, it, expect } from 'vitest';
import { KeySession } from '../../src/core/session';
import { resolveConfig } from '../../src/core/config';
import { TesseraEmitter as EventEmitter } from '../../src/core/events';
import { resetLockout } from '../../src/core/lockout';

// For IndexedDB tests only:
import 'fake-indexeddb/auto';

let session: KeySession;

beforeEach(async () => {
  localStorage.clear();
  resetLockout();
  session = new KeySession();
  await session.init('test-passcode');
});

afterEach(() => {
  session.reset();
});

describe('MyAdapter', () => {
  it('does something', async () => {
    const adapter = new MyAdapter(resolveConfig(), session, new EventEmitter());
    // ...
  });
});
```

**Coverage threshold is 90 % branches.** If you add a code path that branches,
add a test for each branch arm. Use `/* v8 ignore next */` only for genuinely
unreachable defensive guards (e.g. `ENFORCED_FLOORS['x'] ?? fallback` where the
fallback is provably unreachable because the object always has the key).

---

## Adding a new adapter

1. Create `src/adapters/my-adapter.ts`.
2. Implement the appropriate interface from `src/types.ts`.
3. Constructor signature: `(config: ResolvedConfig, session: KeySession, events: TesseraEmitter, suspicion?: SuspicionEngine)`.
4. Use `encryptWithSalt` / `decryptFull` from `src/core/crypto.ts` — never bare `encrypt` / `decrypt`.
5. Use `session.getKey()` for writes, `session.getKeySafe()` for reads.
6. Use `rotateKeyName` / `rotateKeyNameSafe` for all key name → storage key translation.
7. Wire honey keys via `HoneyKeyManager` (see cookie or localStorage adapter for the pattern).
8. Export the adapter from `src/tessera.ts` and add it to the vault object returned by `Tessera.unlock()`.
9. Add a test file under `tests/adapters/`.
10. Add an entry to the config type and `resolveConfig()` if the adapter introduces new config options.

---

## Coding standards

These are enforced by the ESLint config. Violations fail CI.

- **No `any`** — use `unknown` and narrow with type guards.
- **`for...of` over `.forEach()`** and C-style `for` loops.
- **`String.fromCodePoint` / `codePointAt`** over `fromCharCode` / `charCodeAt`.
- **`x !== undefined`** over `typeof x !== 'undefined'`.
- **Hex literals** use groups of 2: `0x80_00`, not `0x8000`.
- **Numeric literals ≥ 5 digits** use `_` separators: `310_000`, not `310000`.
- **`addEventListener('error', ...)`** over `.onerror =` assignment.
- **Explicit return types** on all exported functions.
- **`security/detect-object-injection`** — add an `eslint-disable-next-line` comment when accessing an array/object by loop variable in a clearly safe context (typed arrays, `for...of` with index, Fisher-Yates swaps). Do not blanket-disable the rule.

---

## Release checklist

1. **All CI steps pass** locally: `type-check` → `lint` → `test:coverage` → `build` → `npm audit`.
2. **Bump version** in `package.json` following [Semantic Versioning](https://semver.org):
   - Patch (`0.x.Y`): bug fixes, internal improvements, no API change.
   - Minor (`0.X.0`): new features, no breaking change.
   - Major (`X.0.0`): breaking API changes.
3. **Add CHANGELOG entry** at the top of `CHANGELOG.md` with the date and a summary of all changes.
4. **Update README** changelog section: add a row/section for the new version, update the "latest release" notice.
5. **Check docs**: if the change affects the threat model or introduces a new limitation, update `docs/threat-model.md` or `docs/limitations.md`.
6. **Tag and push**:
   ```bash
   git tag v0.X.Y
   git push origin main --tags
   ```
7. **Publish**:
   ```bash
   npm publish --access public
   ```
   npm will use `.npmignore` to exclude test/dev files from the tarball. Run
   `npm pack --dry-run` first to verify what goes into the package.
