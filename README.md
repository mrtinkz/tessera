# tessera

> *Your data. Your token. Your rules.*

A zero-dependency, ultra-lightweight TypeScript/JavaScript library (~10 KB
gzip) that wraps browser storage (`localStorage`, `sessionStorage`,
`IndexedDB`, cookies) with AES-256-GCM encryption derived from a
user-supplied 6–8 character passcode. No server round-trips. No cloud keys.
No external dependencies.

```ts
import { Tessera } from '@mrtinkz/tessera';

const vault = await Tessera.unlock('abc123');
await vault.local.setItem('cart', JSON.stringify(cartData));
const cart = await vault.local.getItem('cart'); // plaintext
vault.lock(); // zero the in-memory key
```

---

## Features

- **AES-256-GCM** encryption — confidentiality + integrity + authenticity
- **PBKDF2-SHA-256** key derivation at ≥ 310 000 iterations (OWASP 2024)
- **Per-value salt + IV** — stored format: `salt(16) ‖ iv(12) ‖ ct ‖ tag(16)`
- **Non-extractable `CryptoKey`** — raw key bytes never leave the Web Crypto engine
- **Zero runtime dependencies** — 100 % native `globalThis.crypto.subtle`
- **Canvas-based PIN pad** — digit positions randomised; no DOM keylogging surface
- **Idle-timeout auto-lock** with `BroadcastChannel` cross-tab sync
- **Brute-force lockout** — wipe / delay / throw on configurable N attempts
- **SSR-safe** — throws `UNSUPPORTED_ENV` in non-browser contexts with a clear message
- **Universal** — ESM, CJS, IIFE (CDN), React, Vue 3, Svelte, Angular

---

## Installation

```bash
npm install @mrtinkz/tessera
```

---

## Quick Start

### Vanilla JS / TypeScript

```ts
import { Tessera } from '@mrtinkz/tessera';

// Unlock — derives key once per session
const vault = await Tessera.unlock('abc123', {
  iterations: 310_000,       // PBKDF2 iterations (OWASP 2024 minimum)
  idleTimeout: 900_000,      // auto-lock after 15 min idle
  lockoutAttempts: 5,        // wrong passcodes before lockout fires
  lockoutAction: 'wipe',     // 'wipe' | 'delay' | 'throw'
  selectiveKeys: ['cart'],   // only encrypt these keys (omit = encrypt all)
});

// localStorage — drop-in replacement
await vault.local.setItem('cart', JSON.stringify(cartData));
const cart = await vault.local.getItem('cart');
await vault.local.removeItem('cart');

// sessionStorage
await vault.session.setItem('draft', formData);

// Cookies — encrypts value; name + flags stay plaintext
await vault.cookie.set('theme', 'dark', { expires: 7, sameSite: 'Strict' });
const theme = await vault.cookie.get('theme');

// IndexedDB — encrypts values in named object stores
await vault.idb.put('orders', 'order-42', largeObject);
const order = await vault.idb.get('orders', 'order-42');

// Lock
vault.lock();
vault.isLocked(); // true
```

### React

```tsx
// 'use client' is required for Next.js App Router
'use client';
import { useTessera } from '@mrtinkz/tessera/react';
import { renderPinPad } from '@mrtinkz/tessera';

function SecureApp() {
  const { vault, isLocked, unlock, lock } = useTessera({ idleTimeout: 600_000 });

  if (isLocked) {
    return (
      <div
        ref={(el) => {
          if (el) renderPinPad(el, { onUnlock: unlock, randomize: true });
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
    renderPinPad(pinEl, { onUnlock: unlock, randomize: true });
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

### Plain HTML (CDN)

```html
<!--
  The IIFE global is TesseraLib (the module namespace).
  Destructure the exports you need.
-->
<script src="https://cdn.jsdelivr.net/npm/@mrtinkz/tessera/dist/index.global.global.js"></script>
<script>
  const { Tessera, renderPinPad } = TesseraLib;

  Tessera.unlock('abc123').then((vault) => {
    vault.local.setItem('theme', 'dark');
  });
</script>
```

---

## PIN Pad

tessera ships a Canvas-based PIN pad that mitigates keylogging and
click-sequence recording (threat T3). Digit positions are randomised on
every render; no DOM element carries a digit value.

```ts
import { renderPinPad } from '@mrtinkz/tessera';

const cleanup = renderPinPad(document.getElementById('pin')!, {
  onUnlock: async (passcode) => {
    const vault = await Tessera.unlock(passcode);
    // ...
  },
  onError: (remaining) => {
    console.warn(`${remaining} attempts remaining`);
  },
  randomize: true,  // re-shuffle digits on each render (recommended)
  length: 6,        // 6 or 8
});

// Call cleanup() when the PIN pad is no longer needed
cleanup();
```

Style the PIN pad via CSS custom properties:

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

## Configuration reference

| Option | Type | Default | Description |
|---|---|---|---|
| `iterations` | `number` | `310_000` | PBKDF2-SHA-256 iteration count. Must be ≥ 310 000 (OWASP 2024). |
| `idleTimeout` | `number` | `900_000` | Milliseconds of inactivity before auto-lock. |
| `lockoutAttempts` | `number` | `5` | Failed unlock calls before lockout fires. |
| `lockoutAction` | `'wipe' \| 'delay' \| 'throw'` | `'delay'` | Action on lockout: wipe all storage / apply backoff / throw immediately. |
| `lockoutDelay` | `number` | `30_000` | Initial backoff delay (ms) for `'delay'` action; doubles on each trigger. |
| `selectiveKeys` | `string[]` | `[]` | Keys to encrypt. Empty array = encrypt all keys. |

---

## Security model

tessera is designed against the OWASP browser storage threat model. See
[`docs/threat-model.md`](./docs/threat-model.md) for the full threat breakdown
and [`docs/limitations.md`](./docs/limitations.md) for what tessera does **not**
protect against.

**Short summary:**
- Against a passive observer reading DevTools storage: fully protected (T1).
- Against XSS reading storage: ciphertext is useless without the key (T2 partial).
- Against on-page keyloggers: Canvas PIN pad with no DOM key labels (T3).
- Against offline brute force: PBKDF2 cost ~1 s/attempt (T5).
- Against key exfiltration via heap: `extractable: false` (T7).
- Against brute force on device: configurable lockout with wipe option (T8).

---

## Browser support

| Browser | Minimum version |
|---|---|
| Chrome / Edge | 89+ |
| Firefox | 86+ |
| Safari | 15+ |
| Brave | any (Chromium) |
| Opera | 75+ |
| Deno | any (Web Crypto) |
| Bun | any (Web Crypto) |
| Cloudflare Workers | any |

---

## License

MIT
