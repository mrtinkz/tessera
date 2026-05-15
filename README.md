<p align="center">
  <img src="./assets/logo.svg" width="80" alt="tessera" />
</p>

<h1 align="center">tessera</h1>

<p align="center"><em>Your data. Your passcode. Your rules.</em></p>

<p align="center">
  <a href="https://github.com/mrtinkz/tessera/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/mrtinkz/tessera/ci.yml?branch=main&label=build&style=flat-square" alt="Build Status"/></a>
  <a href="https://www.npmjs.com/package/@mrtinkz/tessera"><img src="https://img.shields.io/npm/v/@mrtinkz/tessera?style=flat-square" alt="npm version"/></a>
  <a href="https://bundlephobia.com/package/@mrtinkz/tessera"><img src="https://img.shields.io/bundlephobia/minzip/@mrtinkz/tessera?style=flat-square&label=gzip" alt="Bundle size"/></a>
  <a href="https://www.npmjs.com/package/@mrtinkz/tessera"><img src="https://img.shields.io/npm/dm/@mrtinkz/tessera?style=flat-square" alt="npm downloads"/></a>
  <img src="https://img.shields.io/badge/dependencies-0-brightgreen?style=flat-square" alt="Zero dependencies"/>
  <img src="https://img.shields.io/badge/TypeScript-5-blue?style=flat-square&logo=typescript&logoColor=white" alt="TypeScript"/>
</p>

A zero-dependency TypeScript/JavaScript library (~10 KB gzip) that wraps browser storage — `localStorage`, `sessionStorage`, `IndexedDB`, and cookies — with AES-256-GCM encryption. The encryption key is derived from a user passcode and **never leaves the browser**. No server round-trips. No cloud keys. No external dependencies.

```ts
import { Tessera } from '@mrtinkz/tessera';

const vault = await Tessera.unlock('my-passcode');
await vault.local.setItem('cart', JSON.stringify(cartData));
const cart = await vault.local.getItem('cart'); // decrypted, plaintext
vault.lock(); // zeroes the in-memory key
```

---

## Contents

- [What is tessera?](#what-is-tessera)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Framework Integrations](#framework-integrations)
- [Core Concepts](#core-concepts)
- [Configuration Reference](#configuration-reference)
- [Per-Key Options](#per-key-options)
- [Sensitivity Levels](#sensitivity-levels)
- [Storage Modes (direct · claim · split)](#storage-modes)
- [Events](#events)
- [PIN Pad](#pin-pad)
- [Honey Keys](#honey-keys)
- [Suspicion Engine](#suspicion-engine)
- [Best Practices](#best-practices)
- [Security Model](#security-model)
- [Changelog](#changelog)
- [Browser Support](#browser-support)

---

## What is tessera?

When you store data in `localStorage` or `sessionStorage`, **any JavaScript on the page can read it**. That means an XSS attack, a malicious browser extension, or a curious developer opening DevTools can see everything.

tessera solves this by encrypting every value before it touches storage. The only way to read the data back is to supply the same passcode that encrypted it. Without the passcode, all an attacker sees is random-looking base64.

**It is not a magic bullet.** If an attacker can run JavaScript in your page (full XSS), they can steal the passcode as it is typed. tessera dramatically raises the bar — a stolen storage dump is worthless — but it does not replace good content-security-policy, input sanitisation, and other web hygiene. See [Best Practices](#best-practices).

---

## Installation

```bash
npm install @mrtinkz/tessera
```

CDN (no bundler needed):

```html
<script src="https://cdn.jsdelivr.net/npm/@mrtinkz/tessera/dist/index.global.global.js"></script>
<script>
  const { Tessera, renderPinPad } = TesseraLib;
</script>
```

---

## Quick Start

### The simplest possible example

```ts
import { Tessera } from '@mrtinkz/tessera';

// 1. Unlock — derives the encryption key from the passcode
const vault = await Tessera.unlock('my-passcode');

// 2. Write encrypted data
await vault.local.setItem('username', 'alice');
await vault.session.setItem('token', 'eyJ...');
await vault.cookie.set('theme', 'dark');
await vault.idb.put('orders', 'order-42', { items: [...] });

// 3. Read it back (automatically decrypted)
const username = await vault.local.getItem('username'); // 'alice'
const token    = await vault.session.getItem('token');  // 'eyJ...'
const theme    = await vault.cookie.get('theme');       // 'dark'
const order    = await vault.idb.get('orders', 'order-42');

// 4. Lock — the in-memory key is gone; data is inaccessible until unlock
vault.lock();
```

### Unlock with all options

```ts
const vault = await Tessera.unlock('my-passcode', {
  // --- Key derivation ---
  iterations: 310_000, // PBKDF2-SHA-256 rounds. Minimum 310 000 (OWASP 2024).
  // Higher = slower brute-force. Default: 310 000.

  // --- Session ---
  idleTimeout: 900_000, // Auto-lock after 15 min of no reads/writes. Default: 15 min.

  // --- Lockout ---
  lockoutAttempts: 5, // Wrong passcodes before lockout. Default: 5.
  lockoutAction: 'wipe', // 'wipe' clears all storage on lockout.
  // 'delay' applies exponential backoff (default).
  // 'throw' permanently locks (no wipe).
  lockoutDelay: 30_000, // Initial backoff delay for 'delay' action. Doubles each time.

  // --- Defaults applied to every stored key ---
  defaultSensitivity: 'medium',
  defaults: {
    ttl: 3_600_000, // Keys expire after 1 hour.
    maxReads: 50, // Keys self-destruct after 50 reads.
    onSuspicion: 'wipe', // What to do on HMAC failure: 'wipe' | 'lock' | 'throw'.
  },

  // --- Honey keys (decoy tripwires) ---
  honeyKeys: { count: 3 }, // Add 3 decoy entries to localStorage. Default: 3.

  // --- Half-life (time-based re-authentication) ---
  halfLife: {
    soft: 300_000, // After 5 min: require vault.reconfirm() before access.
    hard: 900_000, // After 15 min: key is deleted regardless.
  },

  // --- Suspicion engine ---
  suspicion: {
    platform: 'desktop', // 'auto' | 'desktop' | 'mobile'
    thresholds: { lockdown: 100 },
  },
});
```

---

## Framework Integrations

### React

```tsx
// 'use client' is required for Next.js App Router
'use client';
import { useTessera } from '@mrtinkz/tessera/react';
import { renderPinPad } from '@mrtinkz/tessera';

function App() {
  const { vault, isLocked, unlock, lock } = useTessera({ idleTimeout: 600_000 });

  if (isLocked) {
    return (
      <div
        ref={(el) => {
          if (el) renderPinPad(el, { onUnlock: unlock, randomize: true, length: 6 });
        }}
      />
    );
  }

  return <Dashboard vault={vault} onLock={lock} />;
}
```

### Vue 3

```vue
<script setup lang="ts">
import { useTessera } from '@mrtinkz/tessera/vue';
import { renderPinPad } from '@mrtinkz/tessera';
import { ref, onMounted } from 'vue';

const { vault, isLocked, unlock, lock } = useTessera({ idleTimeout: 600_000 });
const pinRef = ref<HTMLDivElement | null>(null);

onMounted(() => {
  if (pinRef.value) {
    renderPinPad(pinRef.value, { onUnlock: unlock, randomize: true, length: 6 });
  }
});
</script>

<template>
  <div v-if="isLocked" ref="pinRef" />
  <Dashboard v-else :vault="vault" @lock="lock" />
</template>
```

### Svelte / SvelteKit

```svelte
<script lang="ts">
  import { onMount } from 'svelte';
  import { tesseraStore } from '@mrtinkz/tessera/svelte';
  import { renderPinPad } from '@mrtinkz/tessera';

  const { vault, isLocked, unlock, lock } = tesseraStore({ idleTimeout: 600_000 });
  let pinEl: HTMLDivElement;

  onMount(() => {
    renderPinPad(pinEl, { onUnlock: unlock, randomize: true, length: 6 });
  });
</script>

{#if $isLocked}
  <div bind:this={pinEl} />
{:else}
  <Dashboard vault={$vault} on:lock={lock} />
{/if}
```

### Angular

```typescript
// app.module.ts
import { TesseraModule } from '@mrtinkz/tessera/angular';

@NgModule({
  imports: [TesseraModule.forRoot({ idleTimeout: 600_000 })],
})
export class AppModule {}

// component
import { TesseraService } from '@mrtinkz/tessera/angular';

@Component({ ... })
export class MyComponent {
  constructor(private tessera: TesseraService) {}

  async save(key: string, value: string): Promise<void> {
    await this.tessera.vault?.local.setItem(key, value);
  }
}
```

---

## Core Concepts

### The passcode

The passcode is the secret that unlocks the vault. tessera runs it through PBKDF2-SHA-256 (≥ 310 000 iterations) with a random salt to derive the AES-256-GCM encryption key. **The raw passcode is never stored anywhere** — only the derived key lives in memory.

- Minimum length: **6 characters**
- No maximum length: passphrases, GUIDs, API keys, and PIN numbers all work
- **First unlock** stores an encrypted sentinel so wrong passcodes are detected on all future unlocks
- The key is **non-extractable** — the Web Crypto API prevents JavaScript from ever reading the raw key bytes

### The vault

`Tessera.unlock()` returns a vault object with four storage adapters:

| Adapter         | Usage                                                                 |
| --------------- | --------------------------------------------------------------------- |
| `vault.local`   | `localStorage` — persists across sessions                             |
| `vault.session` | `sessionStorage` — cleared when the tab closes                        |
| `vault.cookie`  | Cookies — survives page reloads; name stays plain, value is encrypted |
| `vault.idb`     | IndexedDB — best for large objects; named object stores               |

### Key rotation

Developer-facing key names (e.g. `'cart'`) are **never written to storage as-is**. tessera runs the developer name through HMAC-SHA256 (keyed with a separate PBKDF2-derived HMAC key) to produce a deterministic, random-looking storage key: `t_` + 32 hex chars. This prevents key name enumeration — an attacker cannot tell which keys are in storage, or even how many real keys there are.

### Locking

Calling `vault.lock()` immediately discards the in-memory key. Any subsequent `getItem` or `setItem` call returns `null` / throws `LOCKED`. The encrypted data remains in storage; it becomes accessible again on the next `Tessera.unlock()` with the correct passcode.

---

## Configuration Reference

All options are optional; defaults are shown.

| Option                          | Type                                        | Default    | Description                                                                                                                                                |
| ------------------------------- | ------------------------------------------- | ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `iterations`                    | `number`                                    | `310_000`  | PBKDF2-SHA-256 iteration count. Must be ≥ 310 000 (OWASP 2024). Increase for higher security on fast hardware.                                             |
| `idleTimeout`                   | `number` (ms)                               | `900_000`  | Auto-lock after this many milliseconds of inactivity. Resets on every read/write.                                                                          |
| `lockoutAttempts`               | `number`                                    | `5`        | Failed `Tessera.unlock()` calls before lockout fires.                                                                                                      |
| `lockoutAction`                 | `'wipe' \| 'delay' \| 'throw'`              | `'delay'`  | **wipe** — clears all storage and throws `LOCKOUT`. **delay** — exponential backoff (no data loss). **throw** — throws `LOCKOUT` immediately, permanently. |
| `lockoutDelay`                  | `number` (ms)                               | `30_000`   | Starting backoff delay for `'delay'` action. Doubles on each lockout trigger.                                                                              |
| `defaultSensitivity`            | `'low' \| 'medium' \| 'high' \| 'critical'` | `'medium'` | Sensitivity preset applied to every key that does not specify its own.                                                                                     |
| `defaults.ttl`                  | `number` (ms)                               | —          | Default time-to-live for all keys. Keys silently expire and self-delete after this duration.                                                               |
| `defaults.maxReads`             | `number`                                    | —          | Default read limit. Keys self-delete after this many reads.                                                                                                |
| `defaults.onSuspicion`          | `'wipe' \| 'lock' \| 'throw'`               | `'wipe'`   | What to do when an HMAC integrity check fails on a stored value.                                                                                           |
| `honeyKeys.count`               | `number`                                    | `3`        | Number of decoy entries added to localStorage after each write. Set to `0` to disable.                                                                     |
| `halfLife.soft`                 | `number` (ms)                               | —          | After this duration, reads require `vault.reconfirm(passcode)` before succeeding.                                                                          |
| `halfLife.hard`                 | `number` (ms)                               | —          | After this duration, the key is deleted unconditionally.                                                                                                   |
| `suspicion.platform`            | `'auto' \| 'desktop' \| 'mobile'`           | `'auto'`   | Tunes visibility-change sensitivity for mobile vs desktop usage patterns.                                                                                  |
| `suspicion.thresholds.lockdown` | `number`                                    | `100`      | Suspicion score that triggers vault lockdown and high-sensitivity key wipe.                                                                                |

---

## Per-Key Options

Every `setItem` / `put` call accepts an options object that overrides the vault-level defaults for that key only.

```ts
await vault.local.setItem('session-token', token, {
  sensitivity: 'critical', // overrides defaultSensitivity
  ttl: 900_000, // self-delete after 15 min
  maxReads: 1, // one-time read (burn-after-reading)
  onSuspicion: 'lock', // lock vault on HMAC failure instead of wiping
  halfLife: {
    soft: 300_000, // require reconfirm after 5 min
    hard: 600_000, // auto-wipe after 10 min
  },
});
```

| Option          | Type                             | Description                                                                                                     |
| --------------- | -------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| `sensitivity`   | `SensitivityLevel`               | `'low'` / `'medium'` / `'high'` / `'critical'`. Controls default TTL, maxReads, and half-life profiles.         |
| `ttl`           | `number` (ms)                    | Key expires and self-deletes after this duration from write time.                                               |
| `maxReads`      | `number`                         | Key self-deletes after this many successful reads. Useful for one-time tokens.                                  |
| `onSuspicion`   | `'wipe' \| 'lock' \| 'throw'`    | Action on HMAC failure: delete the key, lock the vault, or silently return `null`.                              |
| `halfLife.soft` | `number` (ms)                    | Read returns `null` and emits `reconfirmation-required` after this duration; resumes after `vault.reconfirm()`. |
| `halfLife.hard` | `number` (ms)                    | Key is deleted unconditionally after this duration from write time.                                             |
| `mode`          | `'direct' \| 'claim' \| 'split'` | sessionStorage and cookie adapters only — see [Storage Modes](#storage-modes).                                  |

---

## Sensitivity Levels

Sensitivity presets apply a bundled set of defaults. Per-key options always override the preset.

| Level        | TTL    | Max reads | Soft half-life | Notes                                             |
| ------------ | ------ | --------- | -------------- | ------------------------------------------------- |
| `'low'`      | none   | none      | none           | Suitable for preferences, theme settings          |
| `'medium'`   | 1 hour | 50        | none           | Default. Suitable for shopping carts, form drafts |
| `'high'`     | 15 min | 10        | 5 min          | Suitable for session tokens, user IDs             |
| `'critical'` | 5 min  | 3         | 1 min          | Suitable for OTPs, private keys, PII              |

When the vault goes on suspicion lockdown, all `high` and `critical` keys are wiped first.

---

## Storage Modes

`vault.session` and `vault.cookie` support three storage modes, set via `options.mode`.

### `'direct'` (default)

The encrypted value lives directly in sessionStorage / the cookie. Simple and fast.

```ts
await vault.session.setItem('draft', content, { mode: 'direct' });
```

### `'claim'`

A short, opaque claim token lives in sessionStorage / the cookie. The actual encrypted value lives in IndexedDB. Useful when the value is large (cookies have a 4 KB limit) or when you want the session-side to be just a reference.

```ts
await vault.session.setItem('large-blob', data, { mode: 'claim' });
// sessionStorage gets a tiny ref: pointer → IDB has the real ciphertext
```

### `'split'`

The value is XOR-split into two shares. Share A lives in sessionStorage / the cookie; Share B lives in IndexedDB. Neither share alone can reconstruct the value.

```ts
await vault.session.setItem('secret', value, { mode: 'split' });
// Requires both sessionStorage AND IndexedDB to read back
```

---

## Events

Subscribe to vault events to react to security incidents, expirations, and state changes.

```ts
vault.on('vault-locked', ({ reason }) => showLoginScreen(reason));
vault.on('auto-locked', ({ reason }) => showLoginScreen(reason));
vault.on('key-expired', ({ keyAlias, backend }) =>
  console.log(`${keyAlias} expired in ${backend}`),
);
vault.on('max-reads-reached', ({ keyAlias }) => console.log(`${keyAlias} burned after max reads`));
vault.on('hmac-failure', ({ keyAlias }) => console.warn(`Integrity failure on ${keyAlias}`));
vault.on('honey-triggered', ({ backend, score }) =>
  console.warn('Honey key accessed', { backend, score }),
);
vault.on('suspicion-lockdown', ({ reason, score, keysWiped }) => {
  console.error('Vault locked down!', { reason, score, keysWiped });
});
vault.on('reconfirmation-required', ({ keyAlias }) => {
  // Prompt the user to re-enter their passcode
  promptReconfirm().then((p) => vault.reconfirm(p));
});
vault.on('rate-limit-warning', ({ callsPerSecond }) => {
  console.warn(`High read rate: ${callsPerSecond}/s`);
});

// Remove a listener
vault.off('vault-locked', myHandler);
```

### All events

| Event                     | Payload                                    | When                                               |
| ------------------------- | ------------------------------------------ | -------------------------------------------------- |
| `vault-unlocked`          | `{ mode: 'normal' \| 'reconfirm' }`        | After successful `unlock()` or `reconfirm()`       |
| `vault-locked`            | `{ reason: string }`                       | On `lock()`, idle timeout, or lockdown             |
| `auto-locked`             | `{ reason: 'idle-timeout' }`               | On idle timeout specifically                       |
| `key-expired`             | `{ keyAlias, backend, expiredAt }`         | TTL or hard half-life elapsed                      |
| `max-reads-reached`       | `{ keyAlias, backend, reads }`             | Read limit exhausted                               |
| `hmac-failure`            | `{ keyAlias, backend }`                    | Decryption integrity check failed                  |
| `honey-triggered`         | `{ backend, score }`                       | A decoy honey key was accessed                     |
| `suspicion-lockdown`      | `{ reason, score, keysWiped }`             | Suspicion score crossed the lockdown threshold     |
| `reconfirmation-required` | `{ keyAlias, softThresholdMs, elapsedMs }` | Soft half-life elapsed; `vault.reconfirm()` needed |
| `rate-limit-warning`      | `{ callsPerSecond, threshold }`            | Read rate exceeded soft limit                      |
| `storage-quota-warning`   | `{ backend, usedBytes, quotaBytes }`       | Storage near quota (IndexedDB only)                |

### Re-authentication (`vault.reconfirm`)

When a `reconfirmation-required` event fires, the key is still in storage but tessera requires the user to re-verify their identity before returning the value. Call `vault.reconfirm(passcode)` with the correct passcode to resume access.

```ts
vault.on('reconfirmation-required', async ({ keyAlias }) => {
  const passcode = await promptUser(`Re-enter passcode to access ${keyAlias}`);
  try {
    await vault.reconfirm(passcode);
    // Retry the original read — it will succeed now
  } catch {
    // Wrong passcode — handle gracefully
  }
});
```

---

## PIN Pad

tessera ships a canvas-based PIN pad that mitigates keylogging and click-recording attacks. Digit positions are re-randomised after every completed entry; no DOM element carries a digit label that a script could read.

```ts
import { renderPinPad } from '@mrtinkz/tessera';

const cleanup = renderPinPad(document.getElementById('pin')!, {
  onUnlock: async (passcode) => {
    try {
      const vault = await Tessera.unlock(passcode);
      showApp(vault);
    } catch (err) {
      showError(err.message);
    }
  },
  onError: (remaining) => {
    showMessage(`${remaining} attempts remaining`);
  },
  randomize: true, // re-shuffle digit positions on every render (strongly recommended)
  length: 6, // digits required — clamped to [6, 16]
});

// Call cleanup() when the PIN pad unmounts (e.g. React useEffect return)
cleanup();
```

### PIN pad length

| Scenario                | Recommended length | Notes                                                  |
| ----------------------- | ------------------ | ------------------------------------------------------ |
| Consumer app PIN        | 6                  | Minimum enforced by the library                        |
| Banking / high-security | 8–10               | Balance between security and UX                        |
| Internal tools          | 12–16              | Hard upper limit for human-entered PINs                |
| Programmatic unlock     | —                  | Use `Tessera.unlock(apiKey)` directly; no length limit |

The canvas PIN pad only handles digit input (0–9). For passphrase-style unlock (letters, symbols), use a regular `<input type="password">` wired to `Tessera.unlock()`.

### Theming

```css
.tessera-pin-pad {
  --tessera-pad-bg: #1a1a2e;
  --tessera-btn-bg: #16213e;
  --tessera-btn-color: #e2e8f0;
  --tessera-btn-hover: #0f3460;
  --tessera-btn-size: 64px;
  --tessera-indicator-color: #4ade80;
}
```

---

## Honey Keys

After every write, tessera plants N decoy entries in localStorage. These entries look identical to real encrypted keys (`t_` + 32 hex chars with plausible-looking ciphertext). Any code path that touches a honey key increments the suspicion score.

```ts
// Enable 5 honey keys (default is 3)
const vault = await Tessera.unlock(passcode, {
  honeyKeys: { count: 5 },
});

// Listen for honey access
vault.on('honey-triggered', ({ backend, score }) => {
  console.warn(`Honey key accessed on ${backend}. Suspicion score: ${score}`);
});
```

Honey keys are wiped automatically on `vault.lock()` and `vault.terminate()`.

---

## Suspicion Engine

tessera tracks a running suspicion score and locks down the vault if anomalous behaviour is detected. Score contributions:

| Event                     | Score added | Notes                               |
| ------------------------- | ----------- | ----------------------------------- |
| HMAC integrity failure    | +100        | Ciphertext tampered or key mismatch |
| Honey key access          | +50         | Possible storage enumeration        |
| Passcode failure          | +20         | Brute-force attempt                 |
| Rate limit excess         | varies      | Automated read loop                 |
| Visibility-change anomaly | +5          | Tab hidden for suspicious duration  |

When the score reaches the lockdown threshold (default 100), tessera:

1. Locks the vault immediately
2. Wipes all `high` and `critical` sensitivity keys from every backend
3. Emits `suspicion-lockdown` with the list of wiped keys

```ts
const vault = await Tessera.unlock(passcode, {
  suspicion: {
    thresholds: { lockdown: 150 }, // raise the threshold
    platform: 'mobile', // more lenient visibility-change scoring
  },
});

vault.on('suspicion-lockdown', ({ reason, keysWiped }) => {
  console.error(`Vault locked: ${reason}. Wiped: ${keysWiped.join(', ')}`);
  redirectToLoginPage();
});
```

---

## Best Practices

### Passcode strength

```ts
// ❌ Too short — brutable in seconds even with PBKDF2
await Tessera.unlock('123456');

// ✓ Reasonable PIN — 8 digits, ~100M combinations
await Tessera.unlock('84729163');

// ✓ Strong — passphrase, no upper limit
await Tessera.unlock('correct-horse-battery-staple');

// ✓ For automated systems — GUID or random hex
await Tessera.unlock(crypto.randomUUID());
```

### Always handle the locked state

```ts
const value = await vault.local.getItem('token');
if (value === null) {
  // Could be: key doesn't exist, vault is locked, key expired, or HMAC failure.
  // Always handle null — never assume the vault is unlocked.
  redirectToLogin();
  return;
}
```

### Match sensitivity to the data

```ts
// ✓ Use low sensitivity for non-sensitive preferences
await vault.local.setItem('theme', 'dark', { sensitivity: 'low' });

// ✓ Use critical for tokens, PII, keys
await vault.local.setItem('api-key', key, {
  sensitivity: 'critical',
  ttl: 300_000, // 5 minutes
  maxReads: 1, // burn after reading
});
```

### Always terminate when done

```ts
// 'lock' keeps the data in storage for next session
// 'terminate' also clears event listeners and the suspicion engine
vault.terminate(); // call this when the user logs out completely
```

### Use `reconfirm` for sensitive operations

```ts
vault.on('reconfirmation-required', async ({ keyAlias }) => {
  // Don't silently fail — tell the user why you need their passcode again
  const passcode = await showReconfirmDialog(`"${keyAlias}" requires re-authentication`);
  await vault.reconfirm(passcode);
});
```

### React to security events

```ts
// At minimum, redirect to login on lockdown
vault.on('suspicion-lockdown', () => {
  clearUI();
  redirectToLogin();
});

// Log HMAC failures — they may indicate storage tampering
vault.on('hmac-failure', ({ keyAlias, backend }) => {
  logSecurityEvent({ type: 'hmac-failure', key: keyAlias, backend });
});
```

### Use split or claim mode for sensitive session data

```ts
// With mode: 'split', neither sessionStorage NOR IndexedDB alone
// can reconstruct the value — an attacker needs both.
await vault.session.setItem('private-key', key, {
  mode: 'split',
  sensitivity: 'critical',
});
```

### Set `lockoutAction: 'wipe'` for high-security apps

```ts
// If someone exhausts their attempts, wipe everything.
// There is no data worth keeping if someone is brute-forcing the vault.
const vault = await Tessera.unlock(passcode, {
  lockoutAttempts: 5,
  lockoutAction: 'wipe',
});
```

### Never store the passcode

```ts
// ❌ Don't do this
localStorage.setItem('my-passcode', passcode);
sessionStorage.setItem('my-passcode', passcode);

// ✓ Derive the key once per session — that is what Tessera.unlock() is for
const vault = await Tessera.unlock(passcode);
// The passcode can be discarded now; the vault holds the derived key
```

### SSR / server-side rendering

tessera requires `globalThis.crypto.subtle` (the Web Crypto API). In server-rendered frameworks, only call `Tessera.unlock()` in client-side code:

```ts
// Next.js App Router
'use client';

// Vue
onMounted(() => {
  /* unlock here */
});

// SvelteKit
import { browser } from '$app/environment';
if (browser) {
  /* unlock here */
}
```

Calling tessera on the server will throw `UNSUPPORTED_ENV` with a clear message explaining the constraint.

---

## Security Model

tessera targets the [OWASP browser storage threat model](https://owasp.org/www-community/attacks/Browser_Storage_Attacks).

| Threat                                              | Protection                                           | Notes                                                                                             |
| --------------------------------------------------- | ---------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| **T1** Passive storage read (DevTools, file system) | AES-256-GCM encryption                               | All values are ciphertext; key names are rotated to opaque `t_` HMAC hashes                       |
| **T2** XSS reading storage                          | Ciphertext is useless without the derived key        | Does **not** prevent XSS from intercepting the passcode as it is typed                            |
| **T3** Keylogger / click recorder                   | Canvas PIN pad with randomised digit positions       | Click coordinates cannot be mapped to digits without the in-closure zone map                      |
| **T4** Shoulder-surf                                | Digit positions re-randomise on every entry          | An observer who sees your click positions cannot replay them                                      |
| **T5** Offline brute force                          | PBKDF2-SHA-256 ≥ 310 000 iterations + per-value salt | ~1 second per guess on modern hardware; per-value salt defeats rainbow tables                     |
| **T6** Lockout record tampering                     | HMAC-SHA256 signature over the lockout record        | The lockout counter is signed with the passcode-derived key; tampering is detected on next unlock |
| **T7** Key extraction from heap                     | `extractable: false` CryptoKey                       | Raw key bytes can never leave the Web Crypto engine                                               |
| **T8** On-device brute force                        | Lockout with configurable wipe/delay/throw           | Exponential backoff or complete storage wipe after N failures                                     |
| **T9** Ciphertext tampering                         | AES-GCM authentication tag                           | Any byte-level modification is detected before decryption                                         |
| **T10** Cross-tab forced lock (DoS)                 | Authenticated BroadcastChannel messages              | Lock messages carry an AES-GCM proof; tabs that do not hold the vault key cannot forge them       |
| **T11** Split share exposure                        | Share A encrypted before storage                     | In `mode: 'split'`, Share A is encrypted with the vault key before going to sessionStorage        |

### What tessera does NOT protect against

- **Full XSS**: If an attacker can run arbitrary JavaScript in your page, they can steal the passcode as the user types it. tessera protects the stored data, not the input channel.
- **Compromised device**: If the user's OS or browser is compromised, all bets are off.
- **Cookie attributes**: tessera encrypts cookie values but cannot enforce `HttpOnly` or `Secure` flags on cookies it sets through `document.cookie`. Use server-side cookie management for truly sensitive session tokens.
- **Cross-origin attacks**: tessera does not add CORS or CSP headers — those are your application's responsibility.

---

## Changelog

### 0.1.1

Security hardening — no breaking API changes, no migration required.

| Area                  | What changed                                                                                                                                                                                                                                                                                                 |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Key-name rotation     | Switched from AES-GCM (fixed-IV, breaks GCM contract) to HMAC-SHA256. A separate PBKDF2-derived HMAC key is used so the rotation function is a proper PRF.                                                                                                                                                   |
| Lockout record        | Now HMAC-signed after every successful unlock. The signature is verified on the next unlock; a tampered or replayed counter is treated as a lockout.                                                                                                                                                         |
| Split Share A         | Share A (the XOR pad) is now encrypted with the vault key before being written to sessionStorage — consistent with the rest of vault storage.                                                                                                                                                                |
| IDB `updateMetadata`  | Metadata updates inside IndexedDB now use a single `readwrite` transaction, eliminating the TOCTOU race between two sequential connections.                                                                                                                                                                  |
| BroadcastChannel lock | Lock messages now carry an AES-GCM-encrypted proof (`encrypt(key, sentinel)`). Tabs verify the proof before locking; same-origin pages without the vault key cannot trigger a lock.                                                                                                                          |
| Miscellaneous         | Fisher-Yates PIN pad shuffle uses rejection sampling (eliminates modulo bias); claim tokens are now random hex (eliminates sequential-counter IDB collisions); visibility listener is destroyed (not just reset) on `lock()`; whitespace-only passcodes rejected; cookie wipe cleans up internal registries. |

### 0.1.0

Initial release.

---

## Browser Support

| Browser            | Minimum version  |
| ------------------ | ---------------- |
| Chrome / Edge      | 89+              |
| Firefox            | 86+              |
| Safari             | 15+              |
| Brave              | any (Chromium)   |
| Opera              | 75+              |
| Deno               | any (Web Crypto) |
| Bun                | any (Web Crypto) |
| Cloudflare Workers | any              |

---

## License

MIT
