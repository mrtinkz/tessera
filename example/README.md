# tessera — manual test harness

This folder is **gitignored and not published to npm**.
It is a self-contained browser demo that uses the local `dist/` build.

## How to run

1. Build tessera from the project root:
   ```bash
   npm run build
   ```

2. **Serve over HTTP** (required for cookie testing):
   ```bash
   cd example
   npx serve
   # open http://localhost:3000
   ```

   Alternatively use VS Code Live Server (right-click `example/index.html` →
   "Open with Live Server").

   > **Why HTTP?** Browsers block `document.cookie` on the `file://` protocol.
   > localStorage, sessionStorage, and IndexedDB all work fine over `file://`,
   > but cookies require an HTTP origin. The example shows a warning banner
   > when opened directly as a file.

## What it tests

| Feature | Works on `file://`? | Works on `http://localhost`? |
|---|---|---|
| Canvas PIN pad | ✅ | ✅ |
| localStorage | ✅ | ✅ |
| sessionStorage | ✅ | ✅ |
| Cookie | ❌ (browser blocks) | ✅ |
| IndexedDB | ✅ | ✅ |
| Lock / auto-lock | ✅ | ✅ |
| Lockout | ✅ | ✅ |

## Passcode

The built-in PIN pad renders digits 0–9 only. Use a **6-digit numeric passcode**
such as `123456`. Click the six digit circles in order.

> **Cross-session behaviour:** tessera persists a vault salt in `localStorage`
> under the key `tessera_vault_salt`. The same passcode entered in a later
> session derives the **same key** and can decrypt previously stored data.
> If you clear `tessera_vault_salt` (or wipe all storage), the vault resets —
> old ciphertext becomes permanently unreadable.
>
> There is no "wrong passcode" verification — any 6-digit number unlocks
> the vault structure. If you enter a different passcode than the one used to
> encrypt the data, decryption will fail silently (return `null`).

## Verification steps

1. Serve over HTTP, open `http://localhost:3000/example/`
2. Click `1`, `2`, `3`, `4`, `5`, `6` on the PIN pad — vault unlocks (green badge)
3. Use **localStorage → setItem** — inspect DevTools → Application → Local Storage.
   The raw value should be base64 ciphertext, not the plaintext you entered.
4. Use **localStorage → getItem** — should return the original plaintext.
5. Click **Lock vault** — getItem now returns `null`.
6. Unlock again (click 1–2–3–4–5–6) — getItem returns the plaintext again.
7. Test cookies: set → get → confirm value decrypts correctly.
