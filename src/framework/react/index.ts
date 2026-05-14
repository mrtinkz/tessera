import { useState, useCallback, useRef, useEffect } from 'react';
import { Tessera } from '../../tessera';
import type { TesseraConfig, IVault } from '../../types';

export interface UseTesseraReturn {
  vault: IVault | null;
  isLocked: boolean;
  unlock: (passcode: string) => Promise<void>;
  lock: () => void;
}

export function useTessera(config?: TesseraConfig): UseTesseraReturn {
  const [vault, setVault] = useState<IVault | null>(null);
  const [isLocked, setIsLocked] = useState(true);
  const configRef = useRef(config);

  const unlock = useCallback(async (passcode: string) => {
    const v = await Tessera.unlock(passcode, configRef.current);
    setVault(v);
    setIsLocked(false);
  }, []);

  const lock = useCallback(() => {
    vault?.lock();
    setVault(null);
    setIsLocked(true);
  }, [vault]);

  useEffect(() => {
    return () => {
      vault?.lock();
    };
  }, [vault]);

  return { vault, isLocked, unlock, lock };
}


