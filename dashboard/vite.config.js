import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      '/heal':      'http://localhost:8000',
      '/pipeline':  'http://localhost:8000',
      '/pipelines': 'http://localhost:8000',
      '/findings':  'http://localhost:8000',
      '/rl':        'http://localhost:8000',
      '/kb':        'http://localhost:8000',
      '/demo':      'http://localhost:8000',
      '/health':    'http://localhost:8000',
    },
    fs: {
      // Allow Vite dev server to serve files from the contracts directory
      allow: ['..'],
    },
  },
  // Serve contracts/ as static assets so the preset loader can fetch .sol files
  publicDir: path.resolve(__dirname, '../contracts'),
})
