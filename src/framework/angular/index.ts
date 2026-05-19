import { EnvironmentProviders, makeEnvironmentProviders } from '@angular/core';
import { Tessera } from '../../tessera';
import type { TesseraConfig, IVault } from '../../types';

/**
 * Angular service for tessera vault management.
 *
 * No `@Injectable` decorator — tessera's build pipeline (tsup/esbuild) does
 * not run Angular's compiler, so decorator-based ivy metadata is never
 * generated. Add this service to your providers array explicitly:
 *
 * ```ts
 * // Standalone bootstrap (Angular 14+)
 * bootstrapApplication(AppComponent, {
 *   providers: [TesseraService],
 * });
 *
 * // Or per-component:
 * @Component({ providers: [TesseraService], ... })
 * ```
 *
 * For NgModule-based apps, use `TesseraModule.forRoot()`.
 */
export class TesseraService {
  public vault: IVault | null = null;
  public isLocked = true;

  async unlock(passcode: string, config?: TesseraConfig): Promise<IVault> {
    const v = await Tessera.unlock(passcode, config);
    this.vault = v;
    this.isLocked = false;
    return v;
  }

  lock(): void {
    this.vault?.lock();
    this.vault = null;
    this.isLocked = true;
  }
}

/**
 * Provides `TesseraService` for standalone Angular applications (Angular 14+).
 *
 * ```ts
 * bootstrapApplication(AppComponent, {
 *   providers: [provideTessera()],
 * });
 * ```
 */
export function provideTessera(): EnvironmentProviders {
  return makeEnvironmentProviders([TesseraService]);
}

/**
 * NgModule for Angular applications that use NgModule-based architecture.
 *
 * ```ts
 * @NgModule({ imports: [TesseraModule.forRoot()] })
 * export class AppModule {}
 * ```
 */
export const TesseraModule = {
  forRoot(config?: TesseraConfig): { providers: unknown[] } {
    return {
      providers: [TesseraService, { provide: 'TESSERA_CONFIG', useValue: config }],
    };
  },
};
