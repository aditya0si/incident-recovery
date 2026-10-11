import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'

// Same-origin proxy: the browser only ever talks to this console's origin and
// the console forwards API and SSE requests to the loopback API service. In
// Docker the target is http://api:8000 over the internal network; locally it is
// the published loopback API port.
const apiTarget = process.env.CONSOLE_API_TARGET ?? 'http://127.0.0.1:18082'

const apiProxy = {
  target: apiTarget,
  changeOrigin: true,
}

const proxy = {
  '/incidents': apiProxy,
  '/alerts': apiProxy,
  '/demo': apiProxy,
  '/deployment': apiProxy,
  '/healthz': apiProxy,
}

export default defineConfig({
  plugins: [react()],
  server: { host: '127.0.0.1', port: 5173, strictPort: true, proxy },
  preview: { host: '0.0.0.0', port: 4173, strictPort: true, proxy },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: './src/test/setup.ts',
    css: false,
  },
})
