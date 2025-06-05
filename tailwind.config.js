/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
      colors: {
        dark: {
          bg: '#0a0a0b',
          surface: '#111114',
          card: '#1a1a1f',
          border: '#2a2a32',
          text: {
            primary: '#f8fafc',
            secondary: '#cbd5e1',
            muted: '#64748b'
          }
        }
      }
    },
  },
  plugins: [],
}