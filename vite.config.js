import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: 'public/assets',
    rollupOptions: {
      input: 'src/App.jsx',
      output: {
        entryFileNames: 'app.js',
        format: 'umd',
        globals: {
          react: 'React',
          'react-dom': 'ReactDOM',
          'react-router-dom': 'ReactRouterDOM',
          axios: 'axios',
          'socket.io-client': 'io',
          'jwt-decode': 'jwtDecode',
        },
      },
    },
  },
});
