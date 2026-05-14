import { describe, it, expect, vi, beforeEach } from 'vitest';

describe('Angular framework adapter — TesseraService', () => {
  beforeEach(() => {
    vi.mock('@angular/core', () => ({
      Injectable: () => (target: unknown) => target,
      NgModule: () => (target: unknown) => target,
    }));
  });

  it('exports TesseraService class', async () => {
    const { TesseraService } = await import('../../src/framework/angular/index');
    expect(typeof TesseraService).toBe('function');
  });

  it('exports TesseraModule class', async () => {
    const { TesseraModule } = await import('../../src/framework/angular/index');
    expect(typeof TesseraModule).toBe('function');
  });

  it('TesseraService initialises with isLocked true and vault null', async () => {
    const { TesseraService } = await import('../../src/framework/angular/index');
    const svc = new TesseraService();
    expect(svc.isLocked).toBe(true);
    expect(svc.vault).toBeNull();
  });

  it('TesseraService.lock() sets isLocked to true and vault to null', async () => {
    const { TesseraService } = await import('../../src/framework/angular/index');
    const svc = new TesseraService();
    // Inject a fake vault
    const fakeVault = { lock: vi.fn(), isLocked: () => true };
    (svc as unknown as { vault: unknown }).vault = fakeVault;
    svc.isLocked = false;
    svc.lock();
    expect(fakeVault.lock).toHaveBeenCalledTimes(1);
    expect(svc.isLocked).toBe(true);
    expect(svc.vault).toBeNull();
  });

  it('TesseraModule.forRoot() returns an object with ngModule and providers', async () => {
    const { TesseraModule } = await import('../../src/framework/angular/index');
    const result = TesseraModule.forRoot({ iterations: 310_000 });
    expect(result).toHaveProperty('ngModule');
    expect(result).toHaveProperty('providers');
    expect(Array.isArray(result.providers)).toBe(true);
  });
});
