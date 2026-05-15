import { writable, derived } from 'svelte/store';
import { Tessera } from '../../tessera';
import type { TesseraConfig, IVault } from '../../types';

export function tesseraStore(config?: TesseraConfig): {
  vault: { subscribe: import('svelte/store').Readable<IVault | null>['subscribe'] };
  isLocked: { subscribe: import('svelte/store').Readable<boolean>['subscribe'] };
  unlock: (passcode: string) => Promise<void>;
  lock: () => void;
} {
  const vault = writable<IVault | null>(null);
  const unlocked = writable(false);
  const isLocked = derived(unlocked, ($u) => !$u);

  let currentVault: IVault | null = null;

  const unlock = async (passcode: string): Promise<void> => {
    const v = await Tessera.unlock(passcode, config);
    currentVault = v;
    vault.set(v);
    unlocked.set(true);
  };

  const lock = (): void => {
    currentVault?.lock();
    currentVault = null;
    vault.set(null);
    unlocked.set(false);
  };

  return {
    vault: { subscribe: vault.subscribe },
    isLocked: { subscribe: isLocked.subscribe },
    unlock,
    lock,
  };
}
