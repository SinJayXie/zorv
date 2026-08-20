import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import tailwindcss from '@tailwindcss/vite'
import { fileURLToPath, URL } from 'node:url'

// https://vite.dev/config/
export default defineConfig({
  plugins: [vue(), tailwindcss()],
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
        inlineDynamicImports: true,
        entryFileNames: 'assets/zorv-[hash].js',
        assetFileNames: (assetInfo) => {
          if (assetInfo.name?.endsWith('.css')) return 'assets/zorv-[hash].css'
          return 'assets/[name].[ext]'
        },
      },
    },
  },
})
