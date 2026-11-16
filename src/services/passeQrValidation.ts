/**
 * Regras puras e criptograficamente seguras para geração e validação de Passes Virtuais QR.
 * Compartilhadas entre Frontend (controleAcessoService) e Backend (/api/controle-acesso/validar-passe)
 * sem dependências de browser/DOM.
 */

export interface ResultadoRegraPasseQR {
  valido: boolean;
  motivo?: string;
}

const ALFABETO_TOKEN = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

/**
 * Gera token de passe virtual usando Web Crypto CSPRNG (nunca Math.random).
 */
export function gerarTokenPasseSeguro(): string {
  const bytes = new Uint8Array(8);
  if (typeof globalThis.crypto !== 'undefined' && typeof globalThis.crypto.getRandomValues === 'function') {
    globalThis.crypto.getRandomValues(bytes);
  } else {
    throw new Error('Web Crypto API (crypto.getRandomValues) indisponível neste ambiente para gerar token seguro.');
  }

  let p1 = '';
  let p2 = '';
  for (let i = 0; i < 4; i++) {
    p1 += ALFABETO_TOKEN[bytes[i] % ALFABETO_TOKEN.length];
    p2 += ALFABETO_TOKEN[bytes[i + 4] % ALFABETO_TOKEN.length];
  }
  return `PASS-${p1}-${p2}`;
}

export function obterDataEHoraBrasilia(agora: Date = new Date()): { data: string; hora: string } {
  const partes = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'America/Sao_Paulo',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false
  }).formatToParts(agora);

  const map: Record<string, string> = {};
  for (const p of partes) map[p.type] = p.value;
  const horaRaw = map.hour === '24' ? '00' : map.hour || '00';
  return {
    data: `${map.year}-${map.month}-${map.day}`,
    hora: `${horaRaw}:${map.minute || '00'}`
  };
}

function normalizarHoraHHMM(valor?: string | null, padrao: string = '00:00'): string {
  const s = String(valor || '').trim();
  const m = s.match(/^(\d{1,2}):(\d{2})/);
  if (!m) return padrao;
  return `${m[1].padStart(2, '0')}:${m[2]}`;
}

export function validarRegraPasseQR(
  passe: {
    status?: string;
    data_validade?: string;
    hora_inicio?: string;
    hora_fim?: string;
    max_usos?: number;
    limite_usos?: number;
    usos_realizados?: number;
    condominio_id?: string;
  },
  condominioEsperadoId?: string,
  agora: Date = new Date()
): ResultadoRegraPasseQR {
  if (!passe) {
    return { valido: false, motivo: 'Passe Virtual não encontrado.' };
  }

  if (condominioEsperadoId && passe.condominio_id && passe.condominio_id !== condominioEsperadoId) {
    return { valido: false, motivo: 'Passe Virtual pertence a outro condomínio.' };
  }

  const statusAtual = String(passe.status || '').toLowerCase();
  if (statusAtual !== 'valido') {
    return { valido: false, motivo: `Passe está marcado como ${statusAtual.toUpperCase() || 'INVÁLIDO'}.` };
  }

  const { data: hojeBr, hora: horaBr } = obterDataEHoraBrasilia(agora);

  if (passe.data_validade) {
    if (passe.data_validade < hojeBr) {
      return { valido: false, motivo: `Passe expirou na data ${passe.data_validade}.` };
    }
    if (passe.data_validade > hojeBr) {
      return { valido: false, motivo: `Passe válido somente a partir de ${passe.data_validade}.` };
    }
  }

  const horaInicio = normalizarHoraHHMM(passe.hora_inicio, '00:00');
  const horaFim = normalizarHoraHHMM(passe.hora_fim, '23:59');
  if (horaBr < horaInicio || horaBr > horaFim) {
    return {
      valido: false,
      motivo: `Fora da janela de horário autorizada (${horaInicio} às ${horaFim} — horário atual ${horaBr} BRT).`
    };
  }

  const maxUsos = Math.max(1, Number(passe.max_usos ?? passe.limite_usos ?? 1));
  const usosRealizados = Math.max(0, Number(passe.usos_realizados ?? 0));
  if (usosRealizados >= maxUsos) {
    return { valido: false, motivo: 'Limite de utilizações deste passe já foi atingido.' };
  }

  return { valido: true };
}
