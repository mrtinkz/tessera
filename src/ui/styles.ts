export const DEFAULT_STYLES = `
  .tessera-pin-pad {
    --tessera-pad-bg: #ffffff;
    --tessera-btn-bg: #f0f0f0;
    --tessera-btn-color: #1a1a1a;
    --tessera-btn-hover: #e0e0e0;
    --tessera-btn-size: 60px;
    --tessera-gap: 8px;
    --tessera-indicator-size: 14px;
    --tessera-indicator-color: #1a1a1a;
    --tessera-error-color: #d32f2f;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--tessera-gap);
    background: var(--tessera-pad-bg);
    padding: 24px;
    border-radius: 12px;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    user-select: none;
  }

  .tessera-pin-pad-indicators {
    display: flex;
    gap: var(--tessera-gap);
    margin-bottom: 16px;
  }

  .tessera-pin-pad-dot {
    width: var(--tessera-indicator-size);
    height: var(--tessera-indicator-size);
    border-radius: 50%;
    border: 2px solid var(--tessera-indicator-color);
    background: transparent;
    transition: background 0.15s ease;
  }

  .tessera-pin-pad-dot.filled {
    background: var(--tessera-indicator-color);
  }

  .tessera-pin-pad-grid {
    display: grid;
    grid-template-columns: repeat(3, var(--tessera-btn-size));
    gap: var(--tessera-gap);
  }

  .tessera-pin-pad-btn {
    width: var(--tessera-btn-size);
    height: var(--tessera-btn-size);
    border: none;
    border-radius: 50%;
    background: var(--tessera-btn-bg);
    color: var(--tessera-btn-color);
    font-size: 20px;
    font-weight: 500;
    cursor: pointer;
    transition: background 0.15s ease;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .tessera-pin-pad-btn:hover {
    background: var(--tessera-btn-hover);
  }

  .tessera-pin-pad-btn:active {
    transform: scale(0.95);
  }

  .tessera-pin-pad-btn.clear {
    font-size: 12px;
    text-transform: uppercase;
  }

  .tessera-pin-pad-status {
    color: var(--tessera-error-color);
    font-size: 12px;
    min-height: 16px;
    text-align: center;
  }

`;
