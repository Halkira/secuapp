// vite.config.ts
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import fs from 'fs'

export default defineConfig({
  plugins: [react()],
  server: {
    https: {
      key: fs.readFileSync('https/frontend.key'),
      cert: fs.readFileSync('https/frontend.pem'),
    },
    host: true,
    port: 5175,
    proxy: {
      '/api': {
        target: 'https://127.0.0.1:8080',
        changeOrigin: true,
        secure: false,
      },
      '/api/dashcam/v0/ws': {
        target: 'wss://127.0.0.1:8080',
        changeOrigin: true,
        secure: false,
      },
    },
  },
})
