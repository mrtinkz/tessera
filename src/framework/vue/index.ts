import { ref, readonly, onUnmounted } from 'vue';
import { Tessera } from '../../tessera';
import type { TesseraConfig, IVault } from '../../types';

export interface UseTesseraReturn {
  vault: Readonly<import('vue').Ref<IVault | null>>;
  isLocked: Readonly<import('vue').Ref<boolean>>;
  unlock: (passcode: string) => Promise<void>;
  lock: () => void;
}

export function useTessera(config?: TesseraConfig): UseTesseraReturn {
  const vaultRef = ref<IVault | null>(null);
  const lockedRef = ref(true);

  const unlock = async (passcode: string): Promise<void> => {
    const v = await Tessera.unlock(passcode, config);
    vaultRef.value = v;
    lockedRef.value = false;
  };

  const lock = (): void => {
    vaultRef.value?.lock();
    vaultRef.value = null;
    lockedRef.value = true;
  };

  onUnmounted(() => {
    vaultRef.value?.lock();
  });

  return {
    vault: readonly(vaultRef),
    isLocked: readonly(lockedRef),
    unlock,
    lock,
  };
}
