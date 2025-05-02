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
        name: 'App',
        globals: {
          react: 'React',
          'react-dom': 'ReactDOM',
          'react-router-dom': 'ReactRouterDOM',
          axios: 'axios',
          'socket.io-client': 'io',
          'jwt-decode': 'jwtDecode', // Add jwt-decode global
        },
      },
      external: [
        'react',
        'react-dom',
        'react-router-dom',
        'axios',
        'socket.io-client',
        'react/jsx-runtime',
        'jwt-decode', // Externalize jwt-decode
      ],
    },
  },
});
