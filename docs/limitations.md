# tessera — Known Limitations

This document exists so consumers are not given false security guarantees.
tessera is a strong complement to a layered browser security posture, but it
is not a silver bullet.

---

## 1. XSS breaks the model

If an attacker can execute arbitrary JavaScript on the page before tessera
initialises, they can:

- Hook `Tessera.unlock()` to intercept the passcode in plaintext.
- Read the in-memory `CryptoKey` reference from a closure.
- Override adapter methods to log decrypted values.

**Required mitigations:** Deploy a strict Content Security Policy
(`script-src 'self'`), use Subresource Integrity for CDN usage, sanitise
all user input.

### tessera's built-in CSP check

tessera cannot set a CSP — that must come from the server (HTTP header) or
the initial HTML. What it can do is detect whether one is present and warn
you early.

By default (`cspCheck: 'warn'`), if tessera cannot find a
`<meta http-equiv="Content-Security-Policy">` tag or the [Trusted Types API](https://developer.mozilla.org/en-US/docs/Web/API/Trusted_Types_API)
it emits a `csp-warning` event at unlock time so you can surface the gap in
monitoring:

```ts
vault.on('csp-warning', ({ message }) => console.warn('[tessera]', message));
```

| `cspCheck` value     | Behaviour                                                                 |
| -------------------- | ------------------------------------------------------------------------- |
| `'warn'` _(default)_ | Emits `csp-warning` event; does not throw                                 |
| `'require'`          | Throws `UNSUPPORTED_ENV` if no CSP is found — enforces deployment hygiene |
| `false`              | Disables the check (use when CSP is set via HTTP header)                  |

> **Limitation**: a CSP delivered as an **HTTP response header** cannot be
> detected from JavaScript. If your app sets CSP via headers (the recommended
> approach), pass `cspCheck: false` to silence the warning.

---

## 2. Low-entropy numeric PINs

A 6-digit numeric PIN offers only 10⁶ = 1 000 000 combinations. Even at
~1 second per PBKDF2 attempt, an offline attacker who has captured the
ciphertext can exhaust the space in ~11 days on a single CPU core.

For data that needs stronger protection, encourage 6–8 character alphanumeric
passcodes (e.g. `a1B2c3`) which provide ~200 trillion combinations.

---

## 3. Cookies cannot be `httpOnly`

JavaScript must read and write cookie values to encrypt/decrypt them. Cookies
set by tessera therefore cannot carry the `httpOnly` flag, leaving them
accessible to any script on the origin.

The encrypted **value** is protected, but the cookie name and its existence
are visible to all origin scripts. Use `sessionStorage` or `localStorage`
instead of cookies if visibility of the key name is a concern.

---

## 4. In-memory key exposure

The derived `CryptoKey` is `extractable: false` but it still lives in the
JavaScript heap during an active session. A privileged browser extension or a
compromised DevTools session can potentially access the key.

Mitigate by setting a short `idleTimeout` (default: 15 minutes) and calling
`vault.lock()` whenever the user leaves the sensitive section of your app.

---

## 5. Server-Side Rendering (SSR)

tessera detects the absence of `globalThis.crypto.subtle` at runtime and
throws `UNSUPPORTED_ENV`. In SSR frameworks (Next.js, Nuxt, SvelteKit,
Angular SSR), you must guard tessera calls to run only in the browser:

```ts
// Next.js App Router
'use client';

// Vue / SvelteKit
import { onMounted } from 'vue';
onMounted(() => {
  /* tessera code here */
});

// Nuxt 3 — use a .client.ts plugin
```

---

## 6. Supply-chain risk (dependencies)

tessera has **zero runtime dependencies**. Its entire security surface is the
native Web Crypto API. However, the development toolchain (tsup, vitest,
eslint, @angular/core) has known CVEs in the current pinned versions:

| Package                      | Severity | Notes                                                                                                                  |
| ---------------------------- | -------- | ---------------------------------------------------------------------------------------------------------------------- |
| `@angular/core ≤18.2.14`     | HIGH     | Dev-only dependency. Not in the published bundle. XSS in SSR rendering — tessera does not use Angular's SSR rendering. |
| `esbuild ≤0.24.2` (via vite) | MODERATE | Dev server SSRF — only relevant when running `npm run dev`. Not exploitable in CI or production builds.                |

These vulnerabilities affect the **development toolchain only** and are not
present in the published `dist/` bundle which has zero npm dependencies.

---

## 7. `performWipe` is best-effort

When `lockoutAction: 'wipe'` fires, tessera attempts to clear:

- `localStorage` (all keys)
- `sessionStorage` (all keys)
- All cookies via expired-date trick
- The tessera IndexedDB database

Some browsers or browser extensions may block or defer cookie removal. The
IndexedDB deletion is asynchronous. There is no guarantee that all data is
immediately unrecoverable. Do not rely on wipe as a sole data-erasure mechanism
for highly sensitive data.

> **Warning:** `performWipe` calls `localStorage.clear()` — this removes
> **all** localStorage keys on the origin, including keys set by other
> libraries. Use `vault.destroy()` for a scoped teardown that only removes
> tessera's own keys.

---

## 8. Canvas PIN pad and browser extensions

The Canvas-based PIN pad prevents page-level keylogging and click-sequence
recording by JavaScript running in the page context. It does **not** protect
against:

- Browser extensions with content-script access that can read canvas pixels
  or intercept pointer events before they reach the page.
- Screen-capture software (mitigated by the `●` glyph default).
- Physical keyloggers or screen recorders.

---

## 9. GPU-accelerated offline cracking

PBKDF2-SHA-256 at 310 000 iterations costs ~1 second per attempt on a single
CPU core, but modern GPUs achieve ~10 000× more throughput. A 6-digit numeric
PIN can be cracked on a GPU cluster in **under a second**. Always encourage
alphanumeric passcodes of 8+ mixed characters.

---

## 10. `vault.scope()` is a JavaScript guard, not a cryptographic barrier

`vault.scope(keys, ops?)` returns a proxy that restricts which keys can be
accessed and which operations (read vs write) are allowed. This is useful for
passing a limited capability to a sub-component that should not touch the whole
vault.

However, scope limits are enforced in JavaScript only. Any code that holds a
reference to the original unscoped vault object can bypass them entirely. Do not
use `vault.scope()` as a security boundary between mutually distrusting
modules — it is a developer ergonomics tool, not an isolation primitive.

---

## 11. Score decay does not reset graduated threshold events

The suspicion score decays exponentially over time, but the `cautious`,
`guarded`, and `critical` threshold events are fired **once per unlock session**.
If the score decays back below a threshold and then rises again, the event will
not re-fire. Call `vault.lock()` / `vault.reconfirm()` to start a fresh session
with a reset score.

---

## 12. Split-mode orphan cleanup requires a subsequent unlock

When a value is written with `mode: 'split'`, Share A goes to sessionStorage
and Share B to IndexedDB. If the tab is closed or the session is cleared after
the write but before `removeItem()`, Share B remains in IDB as an orphan.

`cleanOrphanedSplits()` runs automatically in the background on every
`Tessera.unlock()`. Orphans from a prior session are removed then. They are
**not** removed during the same session in which they were created, and will
**not** be removed if the vault is never unlocked again (e.g. the user never
returns). In practice this means a small amount of encrypted residue can remain
in IDB for one session after an unclean exit. The data is encrypted and keyed
to the passcode — inaccessible and harmless — but it does not disappear
instantly.

---

## 13. Native storage proxy only catches same-origin script access

At unlock time, tessera installs a proxy on `localStorage.getItem` and
`sessionStorage.getItem`. Scripts that enumerate storage via these standard
methods — XSS payloads, extensions running as content scripts, DevTools
snippets — trip honey detection automatically.

The proxy does **not** intercept:

- `Storage.prototype.getItem.call(localStorage, key)` — direct prototype call
  bypasses the proxy on the instance
- Browser extensions with access to the native storage API at a lower level
- Storage access from service workers on the same origin
- Any code that accesses the `localStorage` object before `Tessera.unlock()` is called
