# tessera — Threat Model

This document describes the threats tessera is designed to mitigate, the attack
vectors it does **not** defend against, and the design decisions that flow from
each threat.

---

## In-scope threats

| ID | Threat | Vector | Mitigation |
|---|---|---|---|
| **T1** | Physical access | An attacker reads browser DevTools storage on a shared or unlocked machine | All values are AES-256-GCM ciphertext — unreadable without the passcode |
| **T2** | XSS exfiltration | Injected script reads `localStorage` or `sessionStorage` | Ciphertext is useless without the derived key; the key is never persisted — it lives only in a JavaScript closure |
| **T3** | Keylogging / click-sequence recording | Malware or injected JS captures keystrokes or click coordinates | The PIN pad renders digits onto a `HTMLCanvasElement`. Pointer events expose only (x, y) coordinates. The digit-zone map lives exclusively in a closure and is never written to the DOM. |
| **T4** | Shoulder surfing | Bystander watches screen during PIN entry | The PIN pad shows `●` glyphs by default; digits are only revealed while the "Hold to reveal" button is pressed |
| **T5** | Offline brute force | Attacker dumps localStorage, runs offline cracker | PBKDF2-SHA-256 at ≥ 310 000 iterations + 128-bit random salt per value ≈ 1 second per attempt on modern hardware |
| **T6** | Man-in-the-middle | Network interception of stored data | tessera operates on storage, not transport. Data is encrypted before any network contact. Complements TLS. |
| **T7** | Key extraction from memory | Attacker reads JS heap or DevTools memory snapshot | `CryptoKey` is `extractable: false` — the Web Crypto API prevents serialisation or exfiltration of raw key bytes |
| **T8** | On-device brute force | Repeated PIN attempts on a public terminal | Configurable lockout: `lockoutAction: 'wipe'` wipes all vault data after N wrong attempts; `'delay'` applies exponential backoff; `'throw'` locks permanently |
| **T9** | Cookie / storage tampering | Attacker modifies an encrypted value in storage | AES-GCM authentication tag detects any byte-level modification and fails decryption before plaintext is recovered |
| **T10** | Timing attacks | Script measures decrypt timing to infer the PIN | Failure and success paths are constant-time within the Web Crypto engine's own implementation |

---

## Cryptographic design

```
Passcode (6–8 chars)
       │
       ▼
  [PBKDF2-SHA-256]  ← 128-bit random salt (unique per stored value)
  ≥ 310 000 iterations
       │
       ▼
  AES-256-GCM Key  (non-extractable CryptoKey — lives in memory only)
       │
       ▼
  [AES-256-GCM Encrypt]  ← 96-bit random IV (unique per encrypt call)
       │
       ▼
  Stored payload = base64( salt(16) ‖ iv(12) ‖ ciphertext ‖ auth-tag(16) )
```

| Component | Choice | Rationale |
|---|---|---|
| Encryption | AES-256-GCM | AEAD — confidentiality + integrity + authenticity in one pass. NIST SP 800-38D. |
| Key derivation | PBKDF2-SHA-256 | RFC 2898. Slows brute force to ~1 s/attempt at 310 K iterations. OWASP 2024 minimum. |
| Salt | 128-bit `crypto.getRandomValues()` | Per-value uniqueness. Prevents rainbow-table attacks. |
| IV | 96-bit `crypto.getRandomValues()` | Per-encrypt-call uniqueness. Prevents GCM nonce reuse. |
| Key extractability | `extractable: false` | Web Crypto guarantee: raw key bits cannot be serialised or posted out of the engine. |
| External crypto libs | None | 100 % native `globalThis.crypto.subtle`. Zero supply-chain attack surface. |

---

## Out-of-scope threats

### XSS is the primary attack that breaks the model (T2 partial)

If an attacker has arbitrary script execution on the page **before tessera
initialises**, they can hook `Tessera.unlock()` and capture the passcode in
plaintext. tessera is a complement to a strong Content Security Policy and
input-sanitisation posture — not a replacement for them.

**Mitigation at the application level:**
- Set a strict CSP (`script-src 'self'`).
- Sanitise all user input with a trusted library.
- Use `Subresource Integrity` on tessera's CDN script tag.

### Passcode entropy

A 6-digit numeric PIN has only 1 000 000 combinations. PBKDF2 cost raises the
per-attempt time but does not create infinite entropy. Consumers should encourage
alphanumeric passcodes (8 mixed characters ≈ 200 trillion combinations).

### In-memory key (T7 partial)

The in-memory derived key can be read by a sufficiently privileged browser
extension or a compromised DevTools session. This threat exists for any
browser-based secret, including session tokens and authentication cookies.

### Cookies cannot be `httpOnly`

The library necessarily writes cookies via JavaScript. The cookie value is
encrypted, but the cookie is readable by any script on the origin. `httpOnly`
cookies must be set server-side.

### Compromised host application

If the application framework itself is compromised (malicious npm dependency,
build-time supply chain attack), the encryption layer can be bypassed. Use npm
provenance attestation and lock file auditing.
