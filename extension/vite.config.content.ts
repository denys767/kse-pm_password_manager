import { defineConfig } from 'vite';
import { resolve } from 'node:path';

/**
 * Separate build pass for the content script: Chrome injects manifest
 * content_scripts as classic (non-module) scripts, so — unlike background.js,
 * which Chrome loads as an MV3 module service worker — content.js cannot
 * contain top-level `import`/`export` statements. This config forces a
 * single self-contained IIFE with no chunk splitting, and does not wipe the
 * dist/ output already produced by the main vite.config.ts build.
 */
export default defineConfig({
    build: {
        outDir: 'dist',
        emptyOutDir: false,
        rollupOptions: {
            input: { content: resolve(__dirname, 'src/content.ts') },
            output: {
                format: 'iife',
                entryFileNames: '[name].js',
                inlineDynamicImports: true,
            },
        },
    },
});
