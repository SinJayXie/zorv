import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import tailwindcss from '@tailwindcss/vite'
import { fileURLToPath, URL } from 'node:url'
import { getBuildVersion } from './get-version.ts'

// https://vite.dev/config/
export default defineConfig({
  plugins: [vue(), tailwindcss()],
  define: {
    // define values are injected as raw JS code, so the version string must be
    // wrapped as a quoted string literal via JSON.stringify; otherwise a bare
    // "1.1.1" is not a valid JS expression and rolldown fails the build.
    'import.meta.env.VITE_BUILD_VERSION': JSON.stringify(getBuildVersion()),
  },
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  build: {
    // Output the build artifacts into the Rust project root html/ dir,
    // which is embedded into the zorvd binary at compile time.
    outDir: '../html',
    emptyOutDir: true,
    // Merge all JS into one chunk and all CSS into one file,
    // so the embedded binary serves exactly one script and one stylesheet.
    // Content hash is kept in the names so the immutable cache on /assets/
    // stays correct after upgrades.
    cssCodeSplit: false,
    rollupOptions: {
      output: {
        // Merge lazy-loaded routes into the single entry chunk
        codeSplitting: false,
        entryFileNames: 'assets/zorv-[hash].js',
        assetFileNames: (assetInfo) => {
          if (assetInfo.name?.endsWith('.css')) return 'assets/zorv-[hash].css'
          return 'assets/[name].[ext]'
        },
      },
    },
  },
})
