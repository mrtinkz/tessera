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
onMounted(() => { /* tessera code here */ });

// Nuxt 3 — use a .client.ts plugin
```

---

## 6. Supply-chain risk (dependencies)

tessera has **zero runtime dependencies**. Its entire security surface is the
native Web Crypto API. However, the development toolchain (tsup, vitest,
eslint, @angular/core) has known CVEs in the current pinned versions:

| Package | Severity | Notes |
|---|---|---|
| `@angular/core ≤18.2.14` | HIGH | Dev-only dependency. Not in the published bundle. XSS in SSR rendering — tessera does not use Angular's SSR rendering. |
| `esbuild ≤0.24.2` (via vite) | MODERATE | Dev server SSRF — only relevant when running `npm run dev`. Not exploitable in CI or production builds. |

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

---

## 8. Canvas PIN pad and browser extensions

The Canvas-based PIN pad prevents page-level keylogging and click-sequence
recording by JavaScript running in the page context. It does **not** protect
against:

- Browser extensions with content-script access that can read canvas pixels
  or intercept pointer events before they reach the page.
- Screen-capture software (mitigated by the `●` glyph default).
- Physical keyloggers or screen recorders.
