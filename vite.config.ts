import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import fs from 'fs';
import path from 'path';
import {defineConfig, loadEnv} from 'vite';

function isSecretBuildKey(val: string): boolean {
  const clean = val.trim();
  if (!clean) return false;
  if (/^sb_secret_/i.test(clean)) return true;
  const parts = clean.split('.');
  if (parts.length === 3 && parts[0].startsWith('eyJ')) {
    try {
      const b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
      const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
      const payload = JSON.parse(Buffer.from(padded, 'base64').toString('utf8'));
      if (String(payload?.role || '').toLowerCase() === 'service_role') return true;
    } catch {
      // ignore non-JWT
    }
  }
  return false;
}

function isValidBuildSupabaseUrl(val: string): boolean {
  const clean = val.trim();
  if (!clean || clean.includes('SEU_PROJETO') || clean.includes('configuracao-pendente')) return false;
  try {
    const parsed = new URL(clean);
    return (parsed.protocol === 'https:' || parsed.protocol === 'http:') && Boolean(parsed.hostname);
  } catch {
    return false;
  }
}

export default defineConfig(({mode}) => {
  const loadedEnv = loadEnv(mode, __dirname, '');
  const mergedEnv = {...loadedEnv, ...process.env};

  const viteUrl = String(mergedEnv.VITE_SUPABASE_URL || '').trim();
  const supaUrl = String(mergedEnv.SUPABASE_URL || '').trim();
  const buildFallbackUrl = !viteUrl && isValidBuildSupabaseUrl(supaUrl) ? supaUrl.replace(/\/+$/, '') : '';

  const viteAnon = String(mergedEnv.VITE_SUPABASE_ANON_KEY || '').trim();
  const supaPub = String(mergedEnv.SUPABASE_PUBLISHABLE_KEY || mergedEnv.SUPABASE_ANON_KEY || '').trim();
  const buildFallbackKey =
    !viteAnon &&
    supaPub.length > 20 &&
    !supaPub.includes('SUA_CHAVE') &&
    !supaPub.includes('configuracao-pendente') &&
    !isSecretBuildKey(supaPub)
      ? supaPub
      : '';

  const buildDefine: Record<string, string> = {};
  if (buildFallbackUrl) {
    buildDefine['import.meta.env.VITE_SUPABASE_URL'] = JSON.stringify(buildFallbackUrl);
  }
  if (buildFallbackKey) {
    buildDefine['import.meta.env.VITE_SUPABASE_ANON_KEY'] = JSON.stringify(buildFallbackKey);
  }

  return {
    define: Object.keys(buildDefine).length > 0 ? buildDefine : undefined,
    plugins: [
      react(),
      tailwindcss(),
      // Copies src/assets into dist/ so root-relative URLs like
      // "/src/assets/images/..." (e.g. generate_image output) still resolve
      // in production builds. Do not remove.
      {
        name: 'copy-unbundled-src-assets',
        apply: 'build',
        closeBundle(error?: Error): void {
          if (error) {
            return;
          }
          const distDir = path.resolve(__dirname, 'dist');
          const srcAssets = path.resolve(__dirname, 'src/assets');
          const distAssets = path.resolve(distDir, 'src/assets');
          if (fs.existsSync(distDir) && fs.existsSync(srcAssets)) {
            fs.cpSync(srcAssets, distAssets, {recursive: true, force: true});
          }
        },
      },
    ],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, '.'),
      },
    },
    server: {
      // HMR is disabled in AI Studio via DISABLE_HMR env var.
      // Do not modify—file watching is disabled to prevent flickering during agent edits.
      hmr: process.env.DISABLE_HMR !== 'true',
      // Disable file watching when DISABLE_HMR is true to save CPU during agent edits.
      watch: process.env.DISABLE_HMR === 'true' ? null : {},
    },
    build: {
      chunkSizeWarningLimit: 800,
      rollupOptions: {
        output: {
          manualChunks(id) {
            if (id.includes('node_modules')) {
              if (id.includes('@supabase')) return 'vendor-supabase';
              if (id.includes('lucide-react')) return 'vendor-lucide';
              if (id.includes('motion')) return 'vendor-motion';
              if (id.includes('react') || id.includes('react-dom')) return 'vendor-react';
            }
          },
        },
      },
    },
  };
});
