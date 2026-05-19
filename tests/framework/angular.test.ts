import { describe, it, expect, vi } from 'vitest';

vi.mock('@angular/core', () => ({
  makeEnvironmentProviders: (providers: unknown[]) => ({ providers }),
  EnvironmentProviders: class {},
}));

describe('Angular framework adapter — TesseraService', () => {
  it('exports TesseraService class', async () => {
    const { TesseraService } = await import('../../src/framework/angular/index');
    expect(typeof TesseraService).toBe('function');
  });

  it('exports TesseraModule object with forRoot()', async () => {
    const { TesseraModule } = await import('../../src/framework/angular/index');
    expect(typeof TesseraModule).toBe('object');
    expect(typeof TesseraModule.forRoot).toBe('function');
  });

  it('exports provideTessera function', async () => {
    const { provideTessera } = await import('../../src/framework/angular/index');
    expect(typeof provideTessera).toBe('function');
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
    const fakeVault = { lock: vi.fn(), isLocked: () => true };
    (svc as unknown as { vault: unknown }).vault = fakeVault;
    svc.isLocked = false;
    svc.lock();
    expect(fakeVault.lock).toHaveBeenCalledTimes(1);
    expect(svc.isLocked).toBe(true);
    expect(svc.vault).toBeNull();
  });

  it('provideTessera() wraps TesseraService via makeEnvironmentProviders', async () => {
    const { provideTessera, TesseraService } = await import('../../src/framework/angular/index');
    const result = provideTessera() as unknown as { providers: unknown[] };
    expect(result.providers).toContain(TesseraService);
  });

  it('TesseraModule.forRoot() returns providers array containing TesseraService', async () => {
    const { TesseraModule, TesseraService } = await import('../../src/framework/angular/index');
    const result = TesseraModule.forRoot({ iterations: 310_000 });
    expect(Array.isArray(result.providers)).toBe(true);
    expect(result.providers).toContain(TesseraService);
  });
});
