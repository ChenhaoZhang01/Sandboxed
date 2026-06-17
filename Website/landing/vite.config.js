import { defineConfig } from 'vite'
import tailwindcss from '@tailwindcss/vite'

// Vite is the dev server + build tool. The Tailwind plugin lets us use
// Tailwind v4 utility classes with zero extra config.
export default defineConfig({
  plugins: [tailwindcss()],
})
