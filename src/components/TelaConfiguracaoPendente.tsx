import React, { useEffect, useState } from 'react';
import { RefreshCw, CheckCircle2, AlertTriangle, Server } from 'lucide-react';
import EmblemaInfport from './EmblemaInfport';
import { obterErroConfiguracaoSupabase } from '../services/supabase';

interface HealthDiagnosticsResponse {
  ok?: boolean;
  workerWorking?: boolean;
  runtime?: string;
  configured?: {
    supabase?: boolean;
    supabaseUrlValid?: boolean;
    supabasePublicKey?: boolean;
    supabaseAdmin?: boolean;
    frontendConfigReady?: boolean;
    upstashRedis?: boolean;
    geminiOcr?: boolean;
  };
  diagnostics?: {
    missingVariables?: string[];
    supabaseUrl?: { source?: string | null; valid?: boolean };
    supabasePublicKey?: { source?: string | null; configured?: boolean };
  };
}

interface TelaConfiguracaoPendenteProps {
  nomeAplicacao: string;
}

export const TelaConfiguracaoPendente: React.FC<TelaConfiguracaoPendenteProps> = ({ nomeAplicacao }) => {
  const [health, setHealth] = useState<HealthDiagnosticsResponse | null>(null);
  const [carregandoHealth, setCarregandoHealth] = useState(true);

  const consultarDiagnostico = async () => {
    setCarregandoHealth(true);
    try {
      const res = await fetch('/api/health', { cache: 'no-store' });
      if (res.ok) {
        const json = (await res.json()) as HealthDiagnosticsResponse;
        setHealth(json);
      }
    } catch {
      setHealth(null);
    } finally {
      setCarregandoHealth(false);
    }
  };

  useEffect(() => {
    consultarDiagnostico();
  }, []);

  const itensDiagnostico = health
    ? [
        {
          label: 'Worker Cloudflare / Backend ativo',
          ok: Boolean(health.ok && health.workerWorking),
          detalhe: health.runtime || 'runtime'
        },
        {
          label: 'SUPABASE_URL (ou VITE_SUPABASE_URL)',
          ok: Boolean(health.configured?.supabaseUrlValid),
          detalhe: health.diagnostics?.supabaseUrl?.source
            ? `Detectada via ${health.diagnostics.supabaseUrl.source}`
            : 'Ausente no runtime do Worker'
        },
        {
          label: 'SUPABASE_PUBLISHABLE_KEY / SUPABASE_ANON_KEY',
          ok: Boolean(health.configured?.supabasePublicKey),
          detalhe: health.diagnostics?.supabasePublicKey?.source
            ? `Detectada via ${health.diagnostics.supabasePublicKey.source}`
            : 'Ausente no runtime do Worker'
        },
        {
          label: 'Chave Administrativa Supabase (Secret backend)',
          ok: Boolean(health.configured?.supabaseAdmin),
          detalhe: health.configured?.supabaseAdmin ? 'Configurada' : 'Ausente no runtime do Worker'
        },
        {
          label: 'Upstash Redis (UPSTASH_REDIS_REST_*)',
          ok: Boolean(health.configured?.upstashRedis),
          detalhe: health.configured?.upstashRedis ? 'Configurado' : 'Não configurado'
        },
        {
          label: 'Gemini OCR (GEMINI_API_KEY)',
          ok: Boolean(health.configured?.geminiOcr),
          detalhe: health.configured?.geminiOcr ? 'Configurada' : 'Opcional / Não configurada'
        }
      ]
    : [];

  return (
    <div className="min-h-screen bg-slate-100 dark:bg-slate-950 flex flex-col items-center justify-center p-4 text-slate-900 dark:text-slate-100">
      <div className="bg-white dark:bg-slate-900 rounded-3xl shadow-2xl w-full max-w-xl p-6 sm:p-8 border border-amber-300 dark:border-amber-800 space-y-4">
        <div className="flex items-center gap-3">
          <EmblemaInfport tamanho="lg" />
          <div>
            <h1 className="text-xl font-black text-slate-900 dark:text-white">{nomeAplicacao}</h1>
            <p className="text-xs font-bold text-amber-600 dark:text-amber-400 uppercase tracking-wider">
              Configuração de Ambiente Pendente
            </p>
          </div>
        </div>

        <div className="p-4 rounded-2xl bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-800 text-xs sm:text-sm text-amber-900 dark:text-amber-200 space-y-2">
          <p className="font-bold">{obterErroConfiguracaoSupabase()}</p>
          <p>
            Por segurança, o sistema não utiliza banco hardcoded no código-fonte. Defina{' '}
            <code className="font-mono font-bold">SUPABASE_URL</code> (ou{' '}
            <code className="font-mono font-bold">VITE_SUPABASE_URL</code>) e{' '}
            <code className="font-mono font-bold">SUPABASE_PUBLISHABLE_KEY</code> /{' '}
            <code className="font-mono font-bold">SUPABASE_ANON_KEY</code> nas{' '}
            <strong>Settings → Variables and Secrets</strong> do Worker{' '}
            <code className="font-mono font-bold">porttohubpro</code> (não apenas em <em>Build variables</em>) e clique em{' '}
            <strong>Deploy</strong>.
          </p>
        </div>

        <div className="p-4 rounded-2xl bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700 space-y-2.5">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-slate-600 dark:text-slate-300">
              <Server className="w-4 h-4" />
              Diagnóstico ao vivo (/api/health)
            </div>
            <button
              type="button"
              onClick={consultarDiagnostico}
              disabled={carregandoHealth}
              className="inline-flex items-center gap-1.5 text-xs font-semibold px-2.5 py-1 rounded-lg bg-slate-200 dark:bg-slate-700 hover:bg-slate-300 dark:hover:bg-slate-600 transition-colors cursor-pointer disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${carregandoHealth ? 'animate-spin' : ''}`} />
              Atualizar
            </button>
          </div>

          {carregandoHealth && !health ? (
            <p className="text-xs text-slate-500 dark:text-slate-400">Consultando runtime do Worker...</p>
          ) : health ? (
            <div className="space-y-1.5">
              {itensDiagnostico.map(item => (
                <div
                  key={item.label}
                  className="flex items-center justify-between gap-3 text-xs py-1 border-b border-slate-200/70 dark:border-slate-700/70 last:border-b-0"
                >
                  <div className="flex items-center gap-2 min-w-0">
                    {item.ok ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-500 shrink-0" />
                    ) : (
                      <AlertTriangle className="w-4 h-4 text-amber-500 shrink-0" />
                    )}
                    <span className="font-medium truncate">{item.label}</span>
                  </div>
                  <span
                    className={`font-mono text-[11px] shrink-0 ${
                      item.ok ? 'text-emerald-600 dark:text-emerald-400' : 'text-amber-600 dark:text-amber-400'
                    }`}
                  >
                    {item.detalhe}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-amber-600 dark:text-amber-400">
              Não foi possível consultar /api/health neste ambiente.
            </p>
          )}
        </div>

        <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
          <a
            href="/api/health"
            target="_blank"
            rel="noopener noreferrer"
            className="text-xs font-mono font-semibold text-indigo-600 dark:text-indigo-400 hover:underline"
          >
            Abrir JSON de /api/health →
          </a>
          <button
            type="button"
            onClick={() => window.location.reload()}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-bold transition-colors cursor-pointer"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Recarregar página
          </button>
        </div>
      </div>
    </div>
  );
};
