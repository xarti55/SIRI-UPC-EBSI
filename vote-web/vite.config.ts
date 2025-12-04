import { defineConfig } from 'vite'

export default defineConfig({
  server: {
    host: '0.0.0.0',  // 0.0.0.0 exposes to the network
    port: 3000         // change this to whatever port you want
  }
})
