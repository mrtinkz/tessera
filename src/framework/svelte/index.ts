import { writable, derived } from 'svelte/store';
import { Tessera } from '../../tessera';
import type { TesseraConfig, IVault } from '../../types';

export function tesseraStore(config?: TesseraConfig) {
  const vault = writable<IVault | null>(null);
  const unlocked = writable(false);
  const isLocked = derived(unlocked, ($u) => !$u);

  let currentVault: IVault | null = null;

  const unlock = async (passcode: string) => {
    const v = await Tessera.unlock(passcode, config);
    currentVault = v;
    vault.set(v);
    unlocked.set(true);
  };

  const lock = () => {
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


