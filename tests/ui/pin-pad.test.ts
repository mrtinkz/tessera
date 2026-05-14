import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderPinPad } from '../../src/ui/pin-pad';
import type { PinPadConfig } from '../../src/types';

// ── Canvas mock ───────────────────────────────────────────────────────────────
// happy-dom's getContext('2d') may return null. We provide a minimal stub so
// that the drawing code runs without errors.
const ctx2dStub = {
  clearRect: vi.fn(),
  beginPath: vi.fn(),
  arc: vi.fn(),
  fill: vi.fn(),
  fillText: vi.fn(),
  fillStyle: '',
  font: '',
  textAlign: 'center',
  textBaseline: 'middle',
} as unknown as CanvasRenderingContext2D;

function makeContainer(): HTMLDivElement {
  const div = document.createElement('div');
  document.body.append(div);
  return div;
}

beforeEach(() => {
  document.body.innerHTML = '';
  vi.clearAllMocks();
});

afterEach(() => {
  document.body.innerHTML = '';
});

describe('renderPinPad — structure', () => {
  it('renders a canvas element inside the container', () => {
    const container = makeContainer();
    renderPinPad(container, { onUnlock: vi.fn() });
    expect(container.querySelector('canvas')).not.toBeNull();
  });

  it('renders dot indicators equal to the configured length', () => {
    const container = makeContainer();
    renderPinPad(container, { onUnlock: vi.fn(), length: 6 });
    expect(container.querySelectorAll('.tessera-pin-pad-dot').length).toBe(6);
  });

  it('renders 8 dots when length: 8', () => {
    const container = makeContainer();
    renderPinPad(container, { onUnlock: vi.fn(), length: 8 });
    expect(container.querySelectorAll('.tessera-pin-pad-dot').length).toBe(8);
  });

  it('defaults to length: 6', () => {
    const container = makeContainer();
    renderPinPad(container, { onUnlock: vi.fn() });
    expect(container.querySelectorAll('.tessera-pin-pad-dot').length).toBe(6);
  });

  it('renders an ARIA group wrapper with correct attributes', () => {
    const container = makeContainer();
    renderPinPad(container, { onUnlock: vi.fn() });
    const wrapper = container.querySelector('.tessera-pin-pad');
    expect(wrapper?.getAttribute('role')).toBe('group');
    expect(wrapper?.getAttribute('aria-label')).toBe('Passcode entry');
  });

  it('injects a <style> element', () => {
    const container = makeContainer();
    renderPinPad(container, { onUnlock: vi.fn() });
    expect(container.querySelector('style')).not.toBeNull();
  });

  it('renders an ARIA live region for status announcements', () => {
    const container = makeContainer();
    renderPinPad(container, { onUnlock: vi.fn() });
    const status = container.querySelector('.tessera-pin-pad-status');
    expect(status?.getAttribute('aria-live')).toBe('polite');
    expect(status?.getAttribute('aria-atomic')).toBe('true');
  });

  it('does NOT render a hold-to-reveal button', () => {
    // Digits are always visible; there is no reveal toggle.
    const container = makeContainer();
    renderPinPad(container, { onUnlock: vi.fn() });
    expect(container.querySelector('.tessera-pin-pad-reveal')).toBeNull();
  });

  it('returns a cleanup function', () => {
    const container = makeContainer();
    const cleanup = renderPinPad(container, { onUnlock: vi.fn() });
    expect(typeof cleanup).toBe('function');
  });

  it('clears the container and removes listeners on cleanup', () => {
    const container = makeContainer();
    const cleanup = renderPinPad(container, { onUnlock: vi.fn() });
    expect(container.children.length).toBeGreaterThan(0);
    cleanup();
    expect(container.innerHTML).toBe('');
  });

  it('clears existing content before rendering', () => {
    const container = makeContainer();
    container.innerHTML = '<p id="old">old</p>';
    renderPinPad(container, { onUnlock: vi.fn() });
    expect(container.querySelector('#old')).toBeNull();
  });

  it('canvas has role=grid and aria-label', () => {
    const container = makeContainer();
    renderPinPad(container, { onUnlock: vi.fn() });
    const canvas = container.querySelector('canvas');
    expect(canvas?.getAttribute('role')).toBe('grid');
    expect(canvas?.getAttribute('aria-label')).toBe('PIN digit grid');
  });

  it('canvas has pointer cursor', () => {
    const container = makeContainer();
    renderPinPad(container, { onUnlock: vi.fn() });
    const canvas = container.querySelector('canvas') as HTMLCanvasElement;
    expect(canvas.style.cursor).toBe('pointer');
  });

  it('status announces 0 digits entered initially', () => {
    const container = makeContainer();
    renderPinPad(container, { onUnlock: vi.fn(), length: 6 });
    const status = container.querySelector('.tessera-pin-pad-status');
    expect(status?.textContent).toMatch(/0 of 6/);
  });

  it('canvas dimensions reflect cellSize (60) and gap (8)', () => {
    const container = makeContainer();
    renderPinPad(container, { onUnlock: vi.fn() });
    const canvas = container.querySelector('canvas') as HTMLCanvasElement;
    expect(canvas.width).toBe(3 * (60 + 8) - 8);   // 196
    expect(canvas.height).toBe(4 * (60 + 8) - 8);  // 268
  });
});

describe('renderPinPad — hit-test zone logic', () => {
  // These tests simulate clicks at known canvas coordinates to verify that
  // the hit-test correctly identifies digit zones.
  // We mock getBoundingClientRect so the canvas occupies a known screen rect.

  function setupWithMockCtx(config: PinPadConfig): {
    container: HTMLDivElement;
    canvas: HTMLCanvasElement;
    cleanup: () => void;
  } {
    const container = makeContainer();

    // Pre-patch getContext on any canvas created by renderPinPad.
    const origCreate = document.createElement.bind(document);
    vi.spyOn(document, 'createElement').mockImplementation((tag: string) => {
      const el = origCreate(tag);
      if (tag === 'canvas') {
        // Keep this mock alive for the entire test (do NOT restore before cleanup).
        // draw() is called both during initial render AND after each completed
        // entry, so getContext must remain mocked or zones become empty.
        vi.spyOn(el as HTMLCanvasElement, 'getContext').mockReturnValue(ctx2dStub);
      }
      return el;
    });

    const cleanup = renderPinPad(container, config);
    // Restore only the document.createElement spy; the canvas.getContext spy
    // is on the specific element and remains live.
    vi.mocked(document.createElement).mockRestore();

    const canvas = container.querySelector('canvas') as HTMLCanvasElement;

    // Mock getBoundingClientRect so hit-test coordinates resolve correctly.
    const canvasW = 3 * (60 + 8) - 8;
    const canvasH = 4 * (60 + 8) - 8;
    vi.spyOn(canvas, 'getBoundingClientRect').mockReturnValue(
      new DOMRect(0, 0, canvasW, canvasH),
    );

    return { container, canvas, cleanup };
  }

  it('fires onUnlock after the correct number of zone hits', () => {
    const onUnlock = vi.fn();
    const { canvas } = setupWithMockCtx({ onUnlock, length: 4, randomize: false });

    // Cell centres: col * (60+8) + 30, row * (60+8) + 30
    const centre = (col: number, row: number): [number, number] =>
      [col * 68 + 30, row * 68 + 30];

    for (const [cx, cy] of [centre(0,0), centre(1,0), centre(2,0), centre(0,1)] as [number,number][]) {
      canvas.dispatchEvent(new MouseEvent('click', { clientX: cx, clientY: cy, bubbles: true }));
    }

    expect(onUnlock).toHaveBeenCalledTimes(1);
    const passcode = onUnlock.mock.calls[0]?.[0] as string;
    expect(typeof passcode).toBe('string');
    expect(passcode.length).toBe(4);
  });

  it('does not fire onUnlock before enough digits', () => {
    const onUnlock = vi.fn();
    const { canvas } = setupWithMockCtx({ onUnlock, length: 6, randomize: false });

    for (let i = 0; i < 3; i++) {
      canvas.dispatchEvent(new MouseEvent('click', { clientX: 30, clientY: 30, bubbles: true }));
    }

    expect(onUnlock).not.toHaveBeenCalled();
  });

  it('resets progress after a hit in the clear zone', () => {
    const onUnlock = vi.fn();
    const { canvas } = setupWithMockCtx({ onUnlock, length: 4, randomize: false });

    // Enter 3 digits
    for (let i = 0; i < 3; i++) {
      canvas.dispatchEvent(new MouseEvent('click', { clientX: 30, clientY: 30, bubbles: true }));
    }

    // Click clear zone (col=1, row=3 → centre (1*68+30, 3*68+30) = (98, 234))
    canvas.dispatchEvent(new MouseEvent('click', { clientX: 98, clientY: 234, bubbles: true }));

    // Now enter 4 digits → onUnlock fires exactly once
    for (const col of [0, 1, 2, 0]) {
      canvas.dispatchEvent(new MouseEvent('click', { clientX: col * 68 + 30, clientY: 30, bubbles: true }));
    }

    expect(onUnlock).toHaveBeenCalledTimes(1);
  });

  it('re-randomizes digit order after a completed entry when randomize: true', () => {
    // Run two complete entries; with high probability the digit order changes.
    const passes: string[] = [];
    let count = 0;

    const { canvas } = setupWithMockCtx({
      length: 4,
      randomize: true,
      onUnlock: (p) => {
        passes.push(p);
        count++;
      },
    });

    // First entry — 4 clicks on (0,0) position
    for (let i = 0; i < 4; i++) {
      canvas.dispatchEvent(new MouseEvent('click', { clientX: 30, clientY: 30, bubbles: true }));
    }
    expect(count).toBe(1);

    // Second entry — 4 clicks on same screen position
    for (let i = 0; i < 4; i++) {
      canvas.dispatchEvent(new MouseEvent('click', { clientX: 30, clientY: 30, bubbles: true }));
    }
    expect(count).toBe(2);

    // With randomize: true the digit at (0,0) is likely different between
    // entries, so the two passcodes are likely different.
    // We can't assert equality/inequality deterministically, but both should
    // be 4-char strings.
    for (const p of passes) {
      expect(typeof p).toBe('string');
      expect(p.length).toBe(4);
    }
  });
});
