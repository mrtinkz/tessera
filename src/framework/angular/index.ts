import { Injectable, NgModule } from '@angular/core';
import { Tessera } from '../../tessera';
import type { TesseraConfig, IVault } from '../../types';

@Injectable({ providedIn: 'root' })
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

@NgModule()
export class TesseraModule {
  static forRoot(config?: TesseraConfig): { ngModule: typeof TesseraModule; providers: unknown[] } {
    return {
      ngModule: TesseraModule,
      providers: [TesseraService, { provide: 'TESSERA_CONFIG', useValue: config }],
    };
  }
}
