import { defineConfig, Plugin } from 'vite';
import { resolve } from 'node:path';
import { readFileSync, writeFileSync } from 'node:fs';

/**
 * Patches externally_connectable in the built manifest with this deployment's
 * app origin. The manifest in public/ carries the localhost dev default —
 * Vite copies it verbatim, so without this every non-dev build would still
 * only trust http://localhost:8080, and the SPA's chrome.runtime.connect
 * bridge would be refused everywhere else.
 */
function patchManifestOrigin(): Plugin {
    return {
        name: 'patch-manifest-origin',
        closeBundle() {
            const origin = (process.env.VITE_API_ORIGIN || 'http://localhost:8080').replace(/\/$/, '');
            const path = resolve(__dirname, 'dist/manifest.json');
            const manifest = JSON.parse(readFileSync(path, 'utf-8'));
            manifest.externally_connectable = { matches: [`${origin}/*`] };
            writeFileSync(path, JSON.stringify(manifest, null, 2));
        },
    };
}

export default defineConfig({
    plugins: [patchManifestOrigin()],
    build: {
        outDir: 'dist',
        emptyOutDir: true,
        rollupOptions: {
            input: {
                popup: resolve(__dirname, 'popup.html'),
                background: resolve(__dirname, 'src/background.ts'),
                offscreen: resolve(__dirname, 'src/offscreen.ts'),
                'crypto-test': resolve(__dirname, 'src/crypto.test.ts'),
                'origin-test': resolve(__dirname, 'src/origin.test.ts'),
                'webauthn-test': resolve(__dirname, 'src/webauthn.test.ts'),
            },
            output: {
                entryFileNames: '[name].js',
                chunkFileNames: 'assets/[name]-[hash].js',
                assetFileNames: 'assets/[name]-[hash][extname]',
            },
        },
    },
});
