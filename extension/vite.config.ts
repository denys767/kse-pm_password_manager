import { defineConfig } from 'vite';
import { resolve } from 'node:path';

export default defineConfig({
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
