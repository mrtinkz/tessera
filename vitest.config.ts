import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'happy-dom',
    coverage: {
      provider: 'v8',
      thresholds: { lines: 90, branches: 90, functions: 90 },
      exclude: ['dist/**', 'example/**', '**/*.test.ts', '*.config.ts'],
    },
  },
});
