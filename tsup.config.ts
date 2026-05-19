import { defineConfig } from 'tsup';

export default defineConfig([
  {
    entry: { index: 'src/tessera.ts' },
    format: ['esm', 'cjs'],
    dts: true,
    // Sourcemaps are kept for local debugging but excluded from the published
    // package via .npmignore — they should never ship to consumers.
    sourcemap: true,
    clean: true,
    minify: false,
    target: 'es2020',
    platform: 'browser',
  },
  {
    entry: { 'index.global': 'src/tessera.ts' },
    format: ['iife'],
    // The IIFE namespace is TesseraLib to avoid colliding with the named
    // export `Tessera` that lives inside it.
    // Usage: const { Tessera, renderPinPad } = TesseraLib;
    globalName: 'TesseraLib',
    minify: true,
    target: 'es2020',
    platform: 'browser',
  },
  {
    entry: { 'react/index': 'src/framework/react/index.ts' },
    format: ['esm', 'cjs'],
    dts: true,
    external: ['react', 'react-dom'],
    platform: 'browser',
  },
  {
    entry: { 'vue/index': 'src/framework/vue/index.ts' },
    format: ['esm', 'cjs'],
    dts: true,
    external: ['vue'],
    platform: 'browser',
  },
  {
    entry: { 'svelte/index': 'src/framework/svelte/index.ts' },
    format: ['esm'],
    dts: true,
    external: ['svelte', 'svelte/store'],
    platform: 'browser',
  },
  {
    entry: { 'angular/index': 'src/framework/angular/index.ts' },
    format: ['esm', 'cjs'],
    dts: true,
    external: ['@angular/core'],
    platform: 'browser',
  },
  {
    // P-20: Standalone pin-pad sub-path — consumers who only need the PIN UI
    // can import '@mrtinkz/tessera/pin-pad' without bundling the full vault.
    entry: { 'pin-pad/index': 'src/ui/pin-pad.ts' },
    format: ['esm', 'cjs'],
    dts: true,
    platform: 'browser',
  },
]);
