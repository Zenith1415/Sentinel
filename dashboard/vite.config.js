import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      '/heal':      'http://localhost:8000',
      '/pipeline':  'http://localhost:8000',
      '/pipelines': 'http://localhost:8000',
      '/kb':        'http://localhost:8000',
    },
  },
})
