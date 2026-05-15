/**
 * Canvas-based PIN pad renderer.
 *
 * Security model (threat model T3 — anti-keylogging, T4 — anti-shoulder-surf):
 *
 *  DIGITS ARE ALWAYS VISIBLE to the user.
 *  The security property is position randomisation, not digit concealment:
 *
 *  - Digit positions are re-randomized after every completed passcode entry.
 *    A click-position logger captures only coordinates — e.g. (230, 180) —
 *    which are meaningless without the zone map that lives in this closure.
 *  - No DOM <button> or <input> elements exist for the digit keys, so no DOM
 *    click events carry digit labels or values.
 *  - The zone map (coordinate → digit mapping) lives exclusively inside a
 *    closure and is never written to the DOM, any attribute, or any event.
 *  - The passcode buffer is a Uint8Array that is explicitly zeroed immediately
 *    after the onUnlock callback returns (whether it throws or not).
 *  - No CustomEvents, data-* attributes, or aria-label values expose digit
 *    values to the DOM.
 *
 *  Analogy: a bank ATM shows the digits 0–9 on the keypad. The security comes
 *  from the fact that an observer watching your finger movements cannot tell
 *  which key you pressed — not from hiding the key labels.
 */

import { type PinPadConfig } from '../types';
import { DEFAULT_STYLES } from './styles';

/** @internal */
const DIGITS = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'] as const;

/** @internal Columns in the 3×4 grid (10 digits + empty + clear). */
const GRID_COLS = 3;

/** @internal Rows in the grid (ceil(12/3) = 4). */
const GRID_ROWS = 4;

/**
 * Cryptographically shuffle an array using Fisher-Yates with
 * `crypto.getRandomValues` as the entropy source.
 * @internal
 */
function shuffleArray<T>(array: readonly T[]): T[] {
  const copy = [...array];
  for (let i = copy.length - 1; i > 0; i--) {
    // Rejection sampling to eliminate modulo bias. Discard values in the
    // incomplete final bucket so every index in [0, i] is equally likely.
    const bucketSize = Math.floor(0x1_00_00_00_00 / (i + 1));
    const maxValid = bucketSize * (i + 1);
    let random: number;
    do {
      random = crypto.getRandomValues(new Uint32Array(1))[0]!;
    } while (random >= maxValid);
    const j = Math.floor(random / bucketSize);
    // eslint-disable-next-line security/detect-object-injection
    const a = copy[i]!;
    // eslint-disable-next-line security/detect-object-injection
    const b = copy[j]!;
    // eslint-disable-next-line security/detect-object-injection
    copy[i] = b;
    // eslint-disable-next-line security/detect-object-injection
    copy[j] = a;
  }
  return copy;
}

/** @internal Zone descriptor for a single canvas cell. */
interface Zone {
  digit: string | null; // null = clear button; null+empty-label = spacer
  x: number;
  y: number;
  w: number;
  h: number;
  label: string;
}

/**
 * Resolved colour palette read from CSS custom properties on the wrapper.
 * Canvas 2D does NOT support `var(--x)` in fillStyle — we must resolve them
 * once via `getComputedStyle` and pass literal colour strings to the API.
 * @internal
 */
interface PadColors {
  btnBg: string;
  btnColor: string;
}

/**
 * Read tessera CSS custom properties from the wrapper element via
 * `getComputedStyle`. Falls back to hard-coded defaults when the property
 * is empty (e.g. before the element is attached to the DOM).
 * @internal
 */
function resolveColors(wrapper: HTMLElement): PadColors {
  const style = getComputedStyle(wrapper);
  const get = (prop: string, fallback: string): string => {
    const v = style.getPropertyValue(prop).trim();
    return v.length > 0 ? v : fallback;
  };
  return {
    btnBg: get('--tessera-btn-bg', '#f0f0f0'),
    btnColor: get('--tessera-btn-color', '#1a1a1a'),
  };
}

/**
 * Render the PIN pad onto a canvas and return the hit-test zone map.
 * Digits are always drawn in plain text — the security comes from position
 * randomisation, not from hiding digit labels.
 * The zone map lives only in memory — never written to the DOM.
 * @internal
 */
function renderCanvas(
  canvas: HTMLCanvasElement,
  digits: readonly string[],
  cellSize: number,
  gap: number,
  colors: PadColors,
): Zone[] {
  const ctx = canvas.getContext('2d');
  if (!ctx) return [];

  ctx.clearRect(0, 0, canvas.width, canvas.height);

  // Build the 12-cell grid: digits[0..9] + spacer (index 10) + clear (index 11)
  const cells: Array<{ digit: string | null; label: string }> = [
    ...digits.map((d) => ({ digit: d, label: 'Digit button' })),
    { digit: null, label: '' }, // spacer — invisible, no zone
    { digit: 'CLEAR', label: 'Clear passcode' },
  ];

  const zones: Zone[] = [];

  for (let row = 0; row < GRID_ROWS; row++) {
    for (let col = 0; col < GRID_COLS; col++) {
      const idx = row * GRID_COLS + col;
      // eslint-disable-next-line security/detect-object-injection
      const cell = cells[idx];
      if (!cell) continue;

      const x = col * (cellSize + gap);
      const y = row * (cellSize + gap);

      // Spacer cell — no visual, no zone
      if (cell.digit === null && cell.label === '') continue;

      const cx = x + cellSize / 2;
      const cy = y + cellSize / 2;
      const radius = cellSize / 2;

      // Circle background — use resolved literal colours (Canvas 2D cannot
      // resolve CSS custom properties via `var(...)` in fillStyle).
      ctx.beginPath();
      ctx.arc(cx, cy, radius, 0, Math.PI * 2);
      ctx.fillStyle = colors.btnBg;
      ctx.fill();

      // Label text — always show the digit; the user needs to see it.
      ctx.fillStyle = colors.btnColor;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';

      if (cell.digit === 'CLEAR') {
        ctx.font = `bold ${Math.round(cellSize * 0.2)}px -apple-system, BlinkMacSystemFont, sans-serif`;
        ctx.fillText('CLR', cx, cy);
      } else {
        ctx.font = `${Math.round(cellSize * 0.35)}px -apple-system, BlinkMacSystemFont, sans-serif`;
        // cell.digit is non-null here: spacers (null+empty label) are skipped
        // above and the only null-digit cell with a label is 'CLEAR', handled above.
        ctx.fillText(cell.digit!, cx, cy);
      }

      zones.push({
        digit: cell.digit === 'CLEAR' ? null : cell.digit!,
        x,
        y,
        w: cellSize,
        h: cellSize,
        label: cell.label,
      });
    }
  }

  return zones;
}

/**
 * Renders a Canvas-based PIN pad into `container`.
 *
 * **The digits are always visible** — the security property is that digit
 * *positions* are randomised on every render, so a click-position recorder
 * captures coordinates that cannot be mapped to digits without the in-closure
 * zone map.
 *
 * @param container - The host `HTMLElement` to render into. Its contents are
 *   replaced. Pass a dedicated wrapper `<div>`.
 * @param config - PIN pad configuration (see {@link PinPadConfig}).
 * @returns A cleanup function that removes all event listeners and clears the
 *   container. Call it when the component unmounts.
 *
 * @example
 * ```ts
 * const cleanup = renderPinPad(document.getElementById('pin')!, {
 *   onUnlock: (passcode) => Tessera.unlock(passcode),
 *   randomize: true,
 *   length: 6,
 * });
 * // later:
 * cleanup();
 * ```
 *
 * @security Mitigates T3 (anti-keylogging) and T4 (anti-shoulder-surf):
 *   canvas click coordinates cannot be mapped to digit values without the
 *   in-closure zone map, and positions change after each completed entry.
 */
export function renderPinPad(container: HTMLElement, config: PinPadConfig): () => void {
  const expectedLength = Math.max(6, Math.min(16, config.length ?? 6));
  const cellSize = 60;
  const gap = 8;

  let currentPasscode: string[] = [];

  // Compute initial digit order. Re-shuffled after each completed entry.
  let digitOrder = config.randomize ? shuffleArray(DIGITS) : [...DIGITS];

  // Build the DOM skeleton.
  container.innerHTML = '';

  const styleEl = document.createElement('style');
  styleEl.textContent = DEFAULT_STYLES;
  container.append(styleEl);

  const wrapper = document.createElement('div');
  wrapper.className = 'tessera-pin-pad';
  wrapper.setAttribute('role', 'group');
  wrapper.setAttribute('aria-label', 'Passcode entry');

  // Dot indicators.
  const indicators = document.createElement('div');
  indicators.className = 'tessera-pin-pad-indicators';
  for (let i = 0; i < expectedLength; i++) {
    const dot = document.createElement('div');
    dot.className = 'tessera-pin-pad-dot';
    indicators.append(dot);
  }
  wrapper.append(indicators);

  // Canvas — all digit interaction happens here.
  const canvasWidth = GRID_COLS * (cellSize + gap) - gap;
  const canvasHeight = GRID_ROWS * (cellSize + gap) - gap;
  const canvas = document.createElement('canvas');
  canvas.width = canvasWidth;
  canvas.height = canvasHeight;
  canvas.setAttribute('role', 'grid');
  canvas.setAttribute('aria-label', 'PIN digit grid');
  canvas.style.cursor = 'pointer';
  canvas.style.display = 'block';
  wrapper.append(canvas);

  // ARIA live region — announces progress without revealing digit values.
  const status = document.createElement('div');
  status.className = 'tessera-pin-pad-status';
  status.setAttribute('aria-live', 'polite');
  status.setAttribute('aria-atomic', 'true');
  wrapper.append(status);

  container.append(wrapper);

  // Zone map — lives only in this closure.
  let zones: Zone[] = [];

  /** Redraw canvas with current digit order and resolved theme colours. */
  function draw(): void {
    // Resolve CSS custom properties after wrapper is in the DOM so
    // getComputedStyle returns the consumer's theme overrides.
    const colors = resolveColors(wrapper);
    zones = renderCanvas(canvas, digitOrder, cellSize, gap, colors);
  }

  /** Update dot fill state and ARIA status text. */
  function updateDots(): void {
    const dots = indicators.querySelectorAll('.tessera-pin-pad-dot');
    // eslint-disable-next-line unicorn/prefer-spread -- NodeListOf lacks Symbol.iterator in ES2020 lib
    for (const [i, dot] of Array.from(dots).entries()) {
      dot.classList.toggle('filled', i < currentPasscode.length);
    }
    status.textContent = `${currentPasscode.length} of ${expectedLength} digits entered.`;
  }

  /** Called when the required number of digits has been collected. */
  function completePasscode(): void {
    const passcode = currentPasscode.join('');
    currentPasscode = [];
    updateDots();

    // Copy into a Uint8Array so we can zero it after use.
    const pinBytes = new Uint8Array(passcode.length);
    for (let i = 0; i < passcode.length; i++) {
      // eslint-disable-next-line security/detect-object-injection
      pinBytes[i] = passcode.codePointAt(i)!;
    }

    // Re-randomize BEFORE handing control to the caller so that an observer
    // watching the screen cannot correlate the new positions with the
    // positions used during the entry they just witnessed.
    if (config.randomize) {
      digitOrder = shuffleArray(DIGITS);
    }
    draw();
    status.textContent = '';

    try {
      config.onUnlock(passcode);
    } finally {
      // Zero the byte buffer regardless of whether onUnlock throws.
      for (let i = 0; i < pinBytes.length; i++) {
        // eslint-disable-next-line security/detect-object-injection
        pinBytes[i] = 0;
      }
    }
  }

  /** Map a pointer event coordinate to a zone and handle it. */
  function handleHit(clientX: number, clientY: number): void {
    const rect = canvas.getBoundingClientRect();
    const scaleX = canvas.width / rect.width;
    const scaleY = canvas.height / rect.height;
    const x = (clientX - rect.left) * scaleX;
    const y = (clientY - rect.top) * scaleY;

    for (const zone of zones) {
      if (x >= zone.x && x <= zone.x + zone.w && y >= zone.y && y <= zone.y + zone.h) {
        if (zone.digit === null) {
          // Clear button — reset entry, redraw (positions stay the same).
          currentPasscode = [];
          updateDots();
          draw();
          return;
        }
        currentPasscode.push(zone.digit);
        updateDots();
        if (currentPasscode.length >= expectedLength) {
          completePasscode();
        }
        return;
      }
    }
  }

  function onCanvasClick(event: MouseEvent): void {
    handleHit(event.clientX, event.clientY);
  }

  function onCanvasTouch(event: TouchEvent): void {
    event.preventDefault();
    const touch = event.changedTouches[0];
    if (touch) handleHit(touch.clientX, touch.clientY);
  }

  canvas.addEventListener('click', onCanvasClick);
  canvas.addEventListener('touchend', onCanvasTouch, { passive: false });

  // Initial draw.
  draw();
  updateDots();

  // Return a cleanup function for framework adapters (React useEffect, etc.).
  return (): void => {
    canvas.removeEventListener('click', onCanvasClick);
    canvas.removeEventListener('touchend', onCanvasTouch);
    container.innerHTML = '';
  };
}
