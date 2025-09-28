import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import fs from 'fs'

// https://vitejs.dev/config/
export default defineConfig({
  base: '/Home',
  plugins: [react()],
  server: {
    https: {
      key: fs.readFileSync('https/frontend.key'),
      cert: fs.readFileSync('https/frontend.pem'),
    },
  },
})