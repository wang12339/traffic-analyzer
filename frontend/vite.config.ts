import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  build: {
    rollupOptions: {
      output: {
        manualChunks(id: string) {
          if (id.includes('node_modules/antd/')) return 'antd';
          if (id.includes('node_modules/recharts')) return 'recharts';
          if (id.includes('node_modules/react/') || id.includes('node_modules/react-dom/')) return 'vendor';
        },
      },
    },
  },
  server: {
    port: 3001, host: '0.0.0.0',
    proxy: {
      '/api': {
        target: 'http://localhost:8970',
        changeOrigin: true,
      },
    },
  },
});
