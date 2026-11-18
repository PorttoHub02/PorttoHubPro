import { supabase, obterAccessTokenAtual, formatarErroDetalhadoSupabase } from './supabase';
import { isUUID } from './condominioService';
import { registrarAtividade } from './auditoriaService';
import { enfileirarAcaoOffline } from './offlineSyncEngine';
import { gerarTokenPasseSeguro, validarRegraPasseQR } from './passeQrValidation';

export interface PontoAcesso {
  id: string;
  condominio_id: string;
  nome: string;
  tipo: 'pedestre' | 'veiculo' | 'misto';
  localizacao: string;
  ativo: boolean;
}

export interface RegistroAcesso {
  id: string;
  condominio_id: string;
  tipo: 'visitante' | 'prestador' | 'convidado_evento' | 'morador' | 'veiculo' | 'entrega';
  nome: string;
  documento: string;
  telefone?: string;
  empresa?: string;
  unidade_bloco: string;
  morador_responsavel?: string;
  ponto_acesso_entrada: string;
  ponto_acesso_saida?: string;
  veiculo_placa?: string;
  veiculo_modelo?: string;
  veiculo_cor?: string;
  data_hora_entrada: string;
  data_hora_saida?: string;
  status: 'presente' | 'saiu' | 'barrado';
  foto_entrada_url?: string;
  foto_saida_url?: string;
  operador_entrada_nome: string;
  operador_saida_nome?: string;
  observacoes?: string;
  cracha_ou_tag?: string;
  reserva_area_id?: string;
  passe_qr_id?: string;
  motivo_bloqueio?: string;
  sincronizado?: boolean;
}

export interface PasseVirtualQR {
  id: string;
  token: string;
  condominio_id: string;
  morador_nome: string;
  morador_telefone?: string;
  unidade_bloco: string;
  visitante_nome: string;
  visitante_documento?: string;
  tipo: 'visitante' | 'festa_convidado' | 'prestador' | 'entrega';
  data_validade: string; // YYYY-MM-DD
  hora_inicio: string;
  hora_fim: string;
  max_usos: number;
  usos_realizados: number;
  status: 'valido' | 'utilizado' | 'expirado' | 'cancelado';
  observacoes?: string;
  criado_em: string;
  sincronizado?: boolean;
}

export interface BloqueioSeguranca {
  id: string;
  condominio_id: string;
  tipo: 'pessoa' | 'veiculo';
  nome_ou_placa: string;
  documento?: string;
  motivo: string;
  gravidade: 'alerta' | 'bloqueio_total' | 'chamar_policia';
  registrado_por: string;
  ativo: boolean;
  criado_em: string;
  sincronizado?: boolean;
}

const CHAVE_STORAGE_PONTOS = 'porttohub_pontos_acesso_';
const CHAVE_STORAGE_REGISTROS = 'porttohub_registros_acesso_';
const CHAVE_STORAGE_PASSES = 'porttohub_passes_virtuais_';
const CHAVE_STORAGE_BLACKLIST = 'porttohub_blacklist_';

export const PONTOS_PADRAO: Omit<PontoAcesso, 'id' | 'condominio_id'>[] = [
  { nome: 'Portaria Principal (Pedestres)', tipo: 'pedestre', localizacao: 'Entrada Social', ativo: true },
  { nome: 'Cancela 01 - Entrada de Veículos', tipo: 'veiculo', localizacao: 'Acesso Garagem', ativo: true },
  { nome: 'Cancela 02 - Saída de Veículos', tipo: 'veiculo', localizacao: 'Saída Garagem', ativo: true },
  { nome: 'Portão de Serviço & Prestadores', tipo: 'pedestre', localizacao: 'Docas / Carga', ativo: true },
  { nome: 'Portão Lateral Pedestres', tipo: 'pedestre', localizacao: 'Acesso Área de Lazer', ativo: true }
];

function ehErroDeRedeOuOffline(err: any): boolean {
  if (typeof navigator !== 'undefined' && !navigator.onLine) return true;
  const msg = String(err?.message || err || '').toLowerCase();
  return (
    msg.includes('failed to fetch') ||
    msg.includes('networkerror') ||
    msg.includes('load failed') ||
    msg.includes('network request failed') ||
    msg.includes('timeout')
  );
}

export async function carregarPontosAcesso(condominioId: string): Promise<PontoAcesso[]> {
  if (!condominioId) return [];

  if (isUUID(condominioId)) {
    try {
      const { data, error } = await supabase
        .from('pontos_acesso')
        .select('*')
        .eq('condominio_id', condominioId)
        .order('nome', { ascending: true });

      if (!error && data && data.length > 0) {
        localStorage.setItem(`${CHAVE_STORAGE_PONTOS}${condominioId}`, JSON.stringify(data));
        return data as PontoAcesso[];
      }
    } catch {}
  }

  const cached = localStorage.getItem(`${CHAVE_STORAGE_PONTOS}${condominioId}`);
  if (cached) {
    try {
      const parsed = JSON.parse(cached);
      if (Array.isArray(parsed) && parsed.length > 0) return parsed;
    } catch {}
  }

  return PONTOS_PADRAO.map((p, i) => ({
    ...p,
    id: `ponto-${condominioId.slice(0, 8)}-${i + 1}`,
    condominio_id: condominioId
  }));
}

export async function carregarRegistrosAcesso(condominioId: string): Promise<RegistroAcesso[]> {
  if (!condominioId) return [];

  if (isUUID(condominioId)) {
    try {
      const { data, error } = await supabase
        .from('registros_acesso')
        .select('*')
        .eq('condominio_id', condominioId)
        .order('data_hora_entrada', { ascending: false })
        .limit(300);

      if (!error && Array.isArray(data)) {
        const normalizados = data.map((r: any) => ({ ...r, sincronizado: true })) as RegistroAcesso[];
        localStorage.setItem(`${CHAVE_STORAGE_REGISTROS}${condominioId}`, JSON.stringify(normalizados));
        return normalizados;
      }
    } catch {}
  }

  const cached = localStorage.getItem(`${CHAVE_STORAGE_REGISTROS}${condominioId}`);
  if (cached) {
    try {
      const parsed = JSON.parse(cached);
      return Array.isArray(parsed) ? parsed : [];
    } catch {}
  }

  return [];
}

export async function carregarBlacklist(condominioId: string): Promise<BloqueioSeguranca[]> {
  if (!condominioId) return [];

  if (isUUID(condominioId)) {
    try {
      const { data, error } = await supabase
        .from('blacklist_bloqueios')
        .select('*')
        .eq('condominio_id', condominioId)
        .order('criado_em', { ascending: false });

      if (!error && Array.isArray(data)) {
        const normalizados = data.map((b: any) => ({ ...b, sincronizado: true })) as BloqueioSeguranca[];
        localStorage.setItem(`${CHAVE_STORAGE_BLACKLIST}${condominioId}`, JSON.stringify(normalizados));
        return normalizados;
      }
    } catch {}
  }

  const cached = localStorage.getItem(`${CHAVE_STORAGE_BLACKLIST}${condominioId}`);
  if (cached) {
    try {
      const parsed = JSON.parse(cached);
      return Array.isArray(parsed) ? parsed : [];
    } catch {}
  }

  return [];
}

export async function verificarBloqueio(
  condominioId: string,
  documento?: string,
  nome?: string,
  placa?: string
): Promise<{ bloqueado: boolean; item?: BloqueioSeguranca }> {
  const lista = await carregarBlacklist(condominioId);
  const ativas = lista.filter(b => b.ativo);

  const docNorm = (documento || '').replace(/\D/g, '');
  const placaNorm = (placa || '').replace(/[^a-zA-Z0-9]/g, '').toUpperCase();
  const nomeNorm = (nome || '').trim().toLowerCase();

  for (const b of ativas) {
    if (b.tipo === 'veiculo' && placaNorm) {
      const bPlaca = b.nome_ou_placa.replace(/[^a-zA-Z0-9]/g, '').toUpperCase();
      if (bPlaca && placaNorm.includes(bPlaca)) {
        return { bloqueado: true, item: b };
      }
    }

    if (b.tipo === 'pessoa') {
      if (docNorm && b.documento) {
        const bDoc = b.documento.replace(/\D/g, '');
        if (bDoc && bDoc === docNorm) {
          return { bloqueado: true, item: b };
        }
      }
      if (nomeNorm && b.nome_ou_placa) {
        if (nomeNorm.includes(b.nome_ou_placa.toLowerCase()) || b.nome_ou_placa.toLowerCase().includes(nomeNorm)) {
          return { bloqueado: true, item: b };
        }
      }
    }
  }

  return { bloqueado: false };
}

export async function salvarItemBlacklist(
  condominioId: string,
  item: Partial<BloqueioSeguranca>,
  operadorLogado?: any
): Promise<{ sucesso: boolean; item?: BloqueioSeguranca; sincronizado?: boolean; erro?: string }> {
  if (!isUUID(condominioId)) {
    return { sucesso: false, erro: 'Condomínio inválido para salvar restrição de segurança.' };
  }

  const lista = await carregarBlacklist(condominioId);
  const id = (item.id && isUUID(item.id))
    ? item.id
    : (typeof crypto !== 'undefined' && crypto.randomUUID ? crypto.randomUUID() : '');

  if (!id) {
    return { sucesso: false, erro: 'Não foi possível gerar UUID seguro para o bloqueio.' };
  }

  const payloadBanco = {
    id,
    condominio_id: condominioId,
    tipo: item.tipo || 'pessoa',
    nome_ou_placa: String(item.nome_ou_placa || '').trim(),
    documento: item.documento || '',
    motivo: item.motivo || 'Sem motivo especificado',
    gravidade: item.gravidade || 'bloqueio_total',
    registrado_por: operadorLogado?.nome || 'Operador',
    ativo: item.ativo !== false,
    criado_em: item.criado_em || new Date().toISOString()
  };

  let sincronizado = false;
  if (typeof navigator !== 'undefined' && !navigator.onLine) {
    enfileirarAcaoOffline('blacklist_bloqueios', 'INSERT', payloadBanco, `Bloqueio: ${payloadBanco.nome_ou_placa}`);
  } else {
    try {
      const { error } = await supabase.from('blacklist_bloqueios').upsert([payloadBanco]);
      if (error) {
        if (ehErroDeRedeOuOffline(error)) {
          enfileirarAcaoOffline('blacklist_bloqueios', 'INSERT', payloadBanco, `Bloqueio: ${payloadBanco.nome_ou_placa}`);
        } else {
          return {
            sucesso: false,
            erro: formatarErroDetalhadoSupabase(error, 'Erro ao gravar bloqueio no servidor')
          };
        }
      } else {
        sincronizado = true;
      }
    } catch (err: any) {
      if (ehErroDeRedeOuOffline(err)) {
        enfileirarAcaoOffline('blacklist_bloqueios', 'INSERT', payloadBanco, `Bloqueio: ${payloadBanco.nome_ou_placa}`);
      } else {
        return {
          sucesso: false,
          erro: formatarErroDetalhadoSupabase(err, 'Erro inesperado ao gravar bloqueio')
        };
      }
    }
  }

  const novo: BloqueioSeguranca = { ...payloadBanco, sincronizado };
  const idx = lista.findIndex(b => b.id === id);
  if (idx >= 0) lista[idx] = novo;
  else lista.unshift(novo);
  localStorage.setItem(`${CHAVE_STORAGE_BLACKLIST}${condominioId}`, JSON.stringify(lista));

  registrarAtividade({
    modulo: 'Controle de Acesso',
    acao: 'BLACKLIST_ATUALIZADA',
    descricao: `Registro na lista de bloqueio/alerta: ${novo.nome_ou_placa} (${novo.gravidade.toUpperCase()}). Motivo: ${novo.motivo}`,
    detalhes: novo,
    operador_nome: operadorLogado?.nome || 'Operador',
    operador_id: operadorLogado?.id,
    condominio_id: condominioId
  });

  return { sucesso: true, item: novo, sincronizado };
}

export async function registrarEntradaAcesso(
  condominioId: string,
  dados: Partial<RegistroAcesso>,
  operadorLogado?: any
): Promise<{ sucesso: boolean; registro?: RegistroAcesso; sincronizado?: boolean; erro?: string; alertaBloqueio?: BloqueioSeguranca }> {
  if (!isUUID(condominioId) || !dados.nome || !dados.unidade_bloco) {
    return { sucesso: false, erro: 'Informe o condomínio válido, nome completo e unidade de destino.' };
  }

  // Checagem de segurança
  const checagem = await verificarBloqueio(condominioId, dados.documento, dados.nome, dados.veiculo_placa);
  if (checagem.bloqueado && checagem.item?.gravidade === 'bloqueio_total') {
    return {
      sucesso: false,
      erro: `ACESSO BARRADO: Consta na Lista de Bloqueios (${checagem.item.motivo})`,
      alertaBloqueio: checagem.item
    };
  }

  const id = (typeof crypto !== 'undefined' && crypto.randomUUID) ? crypto.randomUUID() : '';
  if (!id) {
    return { sucesso: false, erro: 'Não foi possível gerar UUID para registro de acesso.' };
  }

  const payloadBanco = {
    id,
    condominio_id: condominioId,
    tipo: dados.tipo || 'visitante',
    nome: dados.nome.trim(),
    documento: dados.documento || '',
    telefone: dados.telefone || '',
    empresa: dados.empresa || '',
    unidade_bloco: dados.unidade_bloco,
    morador_responsavel: dados.morador_responsavel || '',
    ponto_acesso_entrada: dados.ponto_acesso_entrada || 'Portaria Principal (Pedestres)',
    veiculo_placa: dados.veiculo_placa ? dados.veiculo_placa.toUpperCase().trim() : undefined,
    veiculo_modelo: dados.veiculo_modelo || undefined,
    veiculo_cor: dados.veiculo_cor || undefined,
    data_hora_entrada: dados.data_hora_entrada || new Date().toISOString(),
    status: 'presente' as const,
    foto_entrada_url: dados.foto_entrada_url,
    operador_entrada_nome: operadorLogado?.nome || 'Portaria',
    observacoes: dados.observacoes || '',
    cracha_ou_tag: dados.cracha_ou_tag || '',
    reserva_area_id: (dados.reserva_area_id && isUUID(dados.reserva_area_id)) ? dados.reserva_area_id : undefined,
    passe_qr_id: (dados.passe_qr_id && isUUID(dados.passe_qr_id)) ? dados.passe_qr_id : undefined
  };

  let sincronizado = false;
  if (typeof navigator !== 'undefined' && !navigator.onLine) {
    enfileirarAcaoOffline('registros_acesso', 'INSERT', payloadBanco, `Entrada: ${payloadBanco.nome}`);
  } else {
    try {
      const { error } = await supabase.from('registros_acesso').insert([payloadBanco]);
      if (error) {
        if (ehErroDeRedeOuOffline(error)) {
          enfileirarAcaoOffline('registros_acesso', 'INSERT', payloadBanco, `Entrada: ${payloadBanco.nome}`);
        } else {
          return {
            sucesso: false,
            erro: formatarErroDetalhadoSupabase(error, 'Falha ao persistir entrada no servidor'),
            alertaBloqueio: checagem.item
          };
        }
      } else {
        sincronizado = true;
      }
    } catch (err: any) {
      if (ehErroDeRedeOuOffline(err)) {
        enfileirarAcaoOffline('registros_acesso', 'INSERT', payloadBanco, `Entrada: ${payloadBanco.nome}`);
      } else {
        return {
          sucesso: false,
          erro: formatarErroDetalhadoSupabase(err, 'Erro inesperado ao registrar entrada'),
          alertaBloqueio: checagem.item
        };
      }
    }
  }

  const novo: RegistroAcesso = { ...payloadBanco, sincronizado };
  const registros = await carregarRegistrosAcesso(condominioId);
  registros.unshift(novo);
  localStorage.setItem(`${CHAVE_STORAGE_REGISTROS}${condominioId}`, JSON.stringify(registros));

  registrarAtividade({
    modulo: 'Controle de Acesso',
    acao: 'ENTRADA_REGISTRADA',
    descricao: `Entrada liberada para ${novo.tipo.toUpperCase()}: ${novo.nome}${novo.veiculo_placa ? ` (Placa: ${novo.veiculo_placa})` : ''} -> Unidade ${novo.unidade_bloco} via ${novo.ponto_acesso_entrada}.`,
    detalhes: novo,
    operador_nome: operadorLogado?.nome || 'Operador',
    operador_id: operadorLogado?.id,
    condominio_id: condominioId
  });

  return { sucesso: true, registro: novo, sincronizado, alertaBloqueio: checagem.item };
}

export async function registrarSaidaAcesso(
  condominioId: string,
  registroId: string,
  pontoSaida?: string,
  observacao?: string,
  operadorLogado?: any
): Promise<{ sucesso: boolean; sincronizado?: boolean; erro?: string }> {
  if (!isUUID(condominioId) || !isUUID(registroId)) {
    return { sucesso: false, erro: 'Identificador inválido para registrar saída.' };
  }

  const registros = await carregarRegistrosAcesso(condominioId);
  const reg = registros.find(r => r.id === registroId);
  if (!reg) {
    return { sucesso: false, erro: 'Registro de entrada não encontrado neste condomínio.' };
  }

  const dataHoraSaida = new Date().toISOString();
  const pontoSaidaFinal = pontoSaida || reg.ponto_acesso_entrada || 'Portaria Principal';
  const operadorSaida = operadorLogado?.nome || 'Portaria';
  const obsFinal = observacao
    ? (reg.observacoes ? `${reg.observacoes} | Saída: ${observacao}` : `Saída: ${observacao}`)
    : reg.observacoes;

  const updateFields = {
    status: 'saiu' as const,
    data_hora_saida: dataHoraSaida,
    ponto_acesso_saida: pontoSaidaFinal,
    operador_saida_nome: operadorSaida,
    observacoes: obsFinal
  };

  let sincronizado = false;
  if (typeof navigator !== 'undefined' && !navigator.onLine) {
    enfileirarAcaoOffline(
      'registros_acesso',
      'UPDATE',
      { id: registroId, condominio_id: condominioId, ...updateFields },
      `Saída: ${reg.nome}`
    );
  } else {
    try {
      const { error } = await supabase
        .from('registros_acesso')
        .update(updateFields)
        .eq('id', registroId)
        .eq('condominio_id', condominioId);

      if (error) {
        if (ehErroDeRedeOuOffline(error)) {
          enfileirarAcaoOffline(
            'registros_acesso',
            'UPDATE',
            { id: registroId, condominio_id: condominioId, ...updateFields },
            `Saída: ${reg.nome}`
          );
        } else {
          return {
            sucesso: false,
            erro: formatarErroDetalhadoSupabase(error, 'Erro ao registrar saída no servidor')
          };
        }
      } else {
        sincronizado = true;
      }
    } catch (err: any) {
      if (ehErroDeRedeOuOffline(err)) {
        enfileirarAcaoOffline(
          'registros_acesso',
          'UPDATE',
          { id: registroId, condominio_id: condominioId, ...updateFields },
          `Saída: ${reg.nome}`
        );
      } else {
        return {
          sucesso: false,
          erro: formatarErroDetalhadoSupabase(err, 'Erro inesperado ao registrar saída')
        };
      }
    }
  }

  reg.status = 'saiu';
  reg.data_hora_saida = dataHoraSaida;
  reg.ponto_acesso_saida = pontoSaidaFinal;
  reg.operador_saida_nome = operadorSaida;
  reg.observacoes = obsFinal;
  reg.sincronizado = sincronizado;

  localStorage.setItem(`${CHAVE_STORAGE_REGISTROS}${condominioId}`, JSON.stringify(registros));

  registrarAtividade({
    modulo: 'Controle de Acesso',
    acao: 'SAIDA_REGISTRADA',
    descricao: `Saída registrada para ${reg.nome} (${reg.tipo}) da unidade ${reg.unidade_bloco} via ${reg.ponto_acesso_saida}.`,
    detalhes: { registroId, saida: reg.data_hora_saida },
    operador_nome: operadorLogado?.nome || 'Operador',
    operador_id: operadorLogado?.id,
    condominio_id: condominioId
  });

  return { sucesso: true, sincronizado };
}

export async function carregarPassesVirtuais(condominioId: string): Promise<PasseVirtualQR[]> {
  if (!condominioId) return [];

  if (isUUID(condominioId)) {
    try {
      const { data, error } = await supabase
        .from('passes_virtuais_qr')
        .select('*')
        .eq('condominio_id', condominioId)
        .order('criado_em', { ascending: false });

      if (!error && Array.isArray(data)) {
        const normalizados = data.map((p: any) => ({ ...p, sincronizado: true })) as PasseVirtualQR[];
        localStorage.setItem(`${CHAVE_STORAGE_PASSES}${condominioId}`, JSON.stringify(normalizados));
        return normalizados;
      }
    } catch {}
  }

  const cached = localStorage.getItem(`${CHAVE_STORAGE_PASSES}${condominioId}`);
  if (cached) {
    try {
      const parsed = JSON.parse(cached);
      return Array.isArray(parsed) ? parsed : [];
    } catch {}
  }

  return [];
}

export async function gerarPasseVirtual(
  condominioId: string,
  dados: Partial<PasseVirtualQR>,
  operadorLogado?: any
): Promise<{ sucesso: boolean; passe?: PasseVirtualQR; sincronizado?: boolean; erro?: string }> {
  if (!isUUID(condominioId)) {
    return { sucesso: false, erro: 'Condomínio inválido para emissão de Passe Virtual.' };
  }

  const id = (typeof crypto !== 'undefined' && crypto.randomUUID) ? crypto.randomUUID() : '';
  if (!id) {
    return { sucesso: false, erro: 'Não foi possível gerar UUID para o Passe Virtual.' };
  }

  const token = gerarTokenPasseSeguro();
  const payloadBanco = {
    id,
    token,
    condominio_id: condominioId,
    morador_nome: dados.morador_nome || 'Morador Responsável',
    morador_telefone: dados.morador_telefone || '',
    unidade_bloco: dados.unidade_bloco || 'Geral',
    visitante_nome: dados.visitante_nome || 'Convidado / Visitante',
    visitante_documento: dados.visitante_documento || '',
    tipo: dados.tipo || 'visitante',
    data_validade: dados.data_validade || new Date().toISOString().split('T')[0],
    hora_inicio: dados.hora_inicio || '08:00',
    hora_fim: dados.hora_fim || '22:00',
    max_usos: Math.max(1, Number(dados.max_usos) || 1),
    usos_realizados: 0,
    status: 'valido' as const,
    observacoes: dados.observacoes || '',
    criado_em: new Date().toISOString()
  };

  let sincronizado = false;
  if (typeof navigator !== 'undefined' && !navigator.onLine) {
    enfileirarAcaoOffline('passes_virtuais_qr', 'INSERT', payloadBanco, `Passe QR: ${payloadBanco.token}`);
  } else {
    try {
      const { error } = await supabase.from('passes_virtuais_qr').insert([payloadBanco]);
      if (error) {
        if (ehErroDeRedeOuOffline(error)) {
          enfileirarAcaoOffline('passes_virtuais_qr', 'INSERT', payloadBanco, `Passe QR: ${payloadBanco.token}`);
        } else {
          return {
            sucesso: false,
            erro: formatarErroDetalhadoSupabase(error, 'Erro ao emitir Passe Virtual no servidor')
          };
        }
      } else {
        sincronizado = true;
      }
    } catch (err: any) {
      if (ehErroDeRedeOuOffline(err)) {
        enfileirarAcaoOffline('passes_virtuais_qr', 'INSERT', payloadBanco, `Passe QR: ${payloadBanco.token}`);
      } else {
        return {
          sucesso: false,
          erro: formatarErroDetalhadoSupabase(err, 'Erro inesperado ao emitir Passe Virtual')
        };
      }
    }
  }

  const novo: PasseVirtualQR = { ...payloadBanco, sincronizado };
  const passes = await carregarPassesVirtuais(condominioId);
  passes.unshift(novo);
  localStorage.setItem(`${CHAVE_STORAGE_PASSES}${condominioId}`, JSON.stringify(passes));

  registrarAtividade({
    modulo: 'Controle de Acesso',
    acao: 'PASSE_VIRTUAL_GERADO',
    descricao: `Passe Virtual QR (${novo.token}) emitido para ${novo.visitante_nome} (Destino: ${novo.unidade_bloco} - ${novo.morador_nome}).`,
    detalhes: novo,
    operador_nome: operadorLogado?.nome || 'Operador',
    operador_id: operadorLogado?.id,
    condominio_id: condominioId
  });

  return { sucesso: true, passe: novo, sincronizado };
}

export async function validarTokenPasse(
  condominioId: string,
  codigoOuToken: string
): Promise<{ valido: boolean; passe?: PasseVirtualQR; motivo?: string; alertaBloqueio?: BloqueioSeguranca }> {
  if (!isUUID(condominioId)) {
    return { valido: false, motivo: 'Condomínio inválido para validar Passe Virtual.' };
  }

  const tokenLimpo = (codigoOuToken || '').trim().toUpperCase();
  if (!tokenLimpo) {
    return { valido: false, motivo: 'Informe o código ou leia o QR Code do Passe Virtual.' };
  }

  if (typeof navigator !== 'undefined' && !navigator.onLine) {
    return {
      valido: false,
      motivo: 'Validação de Passe QR bloqueada sem conexão com o servidor para evitar reutilização indevida.'
    };
  }

  try {
    let passe: PasseVirtualQR | null = null;
    const tokenConsulta = codigoOuToken.trim();
    const jwt = await obterAccessTokenAtual();

    if (jwt) {
      try {
        const resp = await fetch('/api/controle-acesso/validar-passe', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${jwt}`
          },
          body: JSON.stringify({
            condominioId,
            token: tokenConsulta,
            consumir: false
          })
        });
        const json: any = await resp.json().catch(() => null);
        if (resp.status !== 404 && resp.status !== 405 && json) {
          if (!resp.ok || !json.valido) {
            return {
              valido: false,
              passe: json.passe as PasseVirtualQR | undefined,
              motivo: json.motivo || 'Passe Virtual inválido ou não encontrado neste condomínio.'
            };
          }
          passe = json.passe as PasseVirtualQR;
        }
      } catch {
        // Prossegue para validação via RPC do Supabase caso rota /api esteja indisponível
      }
    }

    if (!passe) {
      const { data: rpcData, error: rpcErr } = await supabase.rpc('validar_e_consumir_passe_qr', {
        p_condominio_id: condominioId,
        p_token: tokenConsulta,
        p_consumir: false,
        p_ponto_acesso: 'Consulta Portaria',
        p_operador_nome: 'Portaria'
      });

      if (!rpcErr && rpcData) {
        if (!rpcData.valido) {
          return {
            valido: false,
            passe: rpcData.passe as PasseVirtualQR | undefined,
            motivo: rpcData.motivo || 'Passe Virtual inválido ou não encontrado neste condomínio.'
          };
        }
        passe = rpcData.passe as PasseVirtualQR;
      } else if (rpcErr && (rpcErr as any).code !== 'PGRST202') {
        return {
          valido: false,
          motivo: formatarErroDetalhadoSupabase(rpcErr, 'Erro ao validar Passe QR no servidor')
        };
      }
    }

    if (!passe) {
      return { valido: false, motivo: 'Passe Virtual não encontrado neste condomínio.' };
    }

    const regra = validarRegraPasseQR(passe, condominioId);
    if (!regra.valido) {
      return { valido: false, passe, motivo: regra.motivo };
    }

    const checagem = await verificarBloqueio(condominioId, passe.visitante_documento, passe.visitante_nome);
    if (checagem.bloqueado && checagem.item?.gravidade === 'bloqueio_total') {
      return {
        valido: false,
        passe,
        motivo: `ACESSO BARRADO: Visitante consta na Lista de Bloqueios (${checagem.item.motivo}).`,
        alertaBloqueio: checagem.item
      };
    }

    return { valido: true, passe, alertaBloqueio: checagem.item };
  } catch (err: any) {
    return {
      valido: false,
      motivo: formatarErroDetalhadoSupabase(err, 'Falha de comunicação ao validar Passe QR')
    };
  }
}

/**
 * Valida e consome atomicamente 1 uso de Passe Virtual QR via backend seguro (/api/controle-acesso/validar-passe)
 * ou RPC transacional no Supabase PostgreSQL (`validar_e_consumir_passe_qr`), com registro imediato de entrada.
 */
export async function validarEConsumirPasseQR(
  condominioId: string,
  codigoOuToken: string,
  pontoAcesso: string = 'Portaria Principal (Pedestres)',
  operadorLogado?: any
): Promise<{
  sucesso: boolean;
  passe?: PasseVirtualQR;
  registro?: RegistroAcesso;
  motivo?: string;
}> {
  if (!isUUID(condominioId)) {
    return { sucesso: false, motivo: 'Condomínio inválido.' };
  }

  if (typeof navigator !== 'undefined' && !navigator.onLine) {
    return {
      sucesso: false,
      motivo: 'Consumo de Passe QR bloqueado offline. Conecte-se para validar e debitar o uso no servidor.'
    };
  }

  // Verifica lista de bloqueio antes do consumo atômico no servidor
  const preCheck = await validarTokenPasse(condominioId, codigoOuToken);
  if (!preCheck.valido) {
    return { sucesso: false, passe: preCheck.passe, motivo: preCheck.motivo };
  }

  const jwt = await obterAccessTokenAtual();
  if (!jwt) {
    return { sucesso: false, motivo: 'Sessão Supabase Auth ausente. Faça login novamente.' };
  }

  try {
    const resp = await fetch('/api/controle-acesso/validar-passe', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${jwt}`
      },
      body: JSON.stringify({
        condominioId,
        token: codigoOuToken.trim(),
        consumir: true,
        pontoAcesso
      })
    });

    const json: any = await resp.json().catch(() => null);

    if (resp.ok && json?.valido) {
      const passeAtualizado = json.passe as PasseVirtualQR | undefined;
      const registroCriado = json.registro as RegistroAcesso | undefined;

      // Atualiza caches locais com o estado canônico do servidor
      if (passeAtualizado) {
        const passes = await carregarPassesVirtuais(condominioId);
        const atualizados = passes.some(p => p.id === passeAtualizado.id)
          ? passes.map(p => (p.id === passeAtualizado.id ? passeAtualizado : p))
          : [passeAtualizado, ...passes];
        localStorage.setItem(`${CHAVE_STORAGE_PASSES}${condominioId}`, JSON.stringify(atualizados));
      }
      if (registroCriado) {
        const regs = await carregarRegistrosAcesso(condominioId);
        if (!regs.some(r => r.id === registroCriado.id)) {
          regs.unshift({ ...registroCriado, sincronizado: true });
          localStorage.setItem(`${CHAVE_STORAGE_REGISTROS}${condominioId}`, JSON.stringify(regs));
        }
      }

      registrarAtividade({
        modulo: 'Controle de Acesso',
        acao: 'PASSE_QR_CONSUMIDO',
        descricao: `Passe QR ${passeAtualizado?.token || codigoOuToken} validado e consumido para ${passeAtualizado?.visitante_nome || 'Visitante'} via ${pontoAcesso}.`,
        detalhes: { passeId: passeAtualizado?.id, usos: passeAtualizado?.usos_realizados },
        operador_nome: operadorLogado?.nome || 'Operador',
        operador_id: operadorLogado?.id,
        condominio_id: condominioId
      });

      return { sucesso: true, passe: passeAtualizado, registro: registroCriado };
    }

    if (resp.status !== 404 && resp.status !== 405 && json?.motivo) {
      return { sucesso: false, passe: json?.passe, motivo: json.motivo };
    }

    // Fallback direto para RPC transacional no Supabase caso rota /api não esteja montada no ambiente estático
    const { data: rpcData, error: rpcErr } = await supabase.rpc('validar_e_consumir_passe_qr', {
      p_condominio_id: condominioId,
      p_token: codigoOuToken.trim(),
      p_consumir: true,
      p_ponto_acesso: pontoAcesso,
      p_operador_nome: operadorLogado?.nome || operadorLogado?.login || 'Portaria'
    });

    if (rpcErr) {
      return { sucesso: false, motivo: formatarErroDetalhadoSupabase(rpcErr, 'Erro na validação atômica do Passe QR') };
    }

    if (!rpcData?.valido) {
      return { sucesso: false, passe: rpcData?.passe, motivo: rpcData?.motivo || 'Passe QR inválido.' };
    }

    return {
      sucesso: true,
      passe: rpcData.passe as PasseVirtualQR,
      registro: rpcData.registro as RegistroAcesso
    };
  } catch (err: any) {
    return {
      sucesso: false,
      motivo: formatarErroDetalhadoSupabase(err, 'Falha ao consumir Passe QR no servidor')
    };
  }
}

export function formatarMensagemWhatsAppPasse(passe: PasseVirtualQR, condominioNome: string): string {
  const dataFormatada = new Date(passe.data_validade + 'T12:00:00').toLocaleDateString('pt-BR');
  let msg = `*PORTTOHUB - ${condominioNome.toUpperCase()}*\n`;
  msg += `🎫 *CONVITE & PASSE VIRTUAL DE ACESSO*\n\n`;
  msg += `Olá, *${passe.visitante_nome}*!\n`;
  msg += `Você possui autorização de entrada pré-aprovada para:\n\n`;
  msg += `🏠 *Unidade de Destino:* ${passe.unidade_bloco}\n`;
  msg += `👤 *Anfitrião(ã):* ${passe.morador_nome}\n`;
  msg += `📅 *Válido para o Dia:* ${dataFormatada}\n`;
  msg += `⏰ *Janela de Horário:* Das ${passe.hora_inicio} às ${passe.hora_fim}\n`;
  msg += `🔑 *CÓDIGO DE ACESSO:* \`${passe.token}\`\n\n`;
  if (passe.observacoes) {
    msg += `📌 *Nota:* ${passe.observacoes}\n\n`;
  }
  msg += `Ao chegar na guarita/portaria, apresente este código ou informe ao operador para liberação imediata e ágil sem burocracia!\n`;
  msg += `_Emitido com segurança via PorttoHub._`;
  return msg;
}

// --- INTEGRAÇÃO COM MÓDULO DE CADASTRO BASE, MORADORES E UNIDADES ---

export interface MoradorBaseInfo {
  id: string;
  nome: string;
  bloco?: string;
  unidade: string;
  telefone?: string;
  email?: string;
  cpf?: string;
  rg?: string;
  tipo?: string;
  condominio_id: string;
  tag_rfid?: string;
  codigo_acesso?: string;
  status_acesso?: 'liberado' | 'bloqueado' | string;
  veiculo_placa?: string;
  veiculo_modelo?: string;
  veiculo_cor?: string;
  foto_url?: string;
  foto_base64?: string;
  contato_emergencia?: string;
  observacoes?: string;
}

export async function carregarMoradoresBase(condominioId: string): Promise<MoradorBaseInfo[]> {
  if (!condominioId || condominioId === 'global' || condominioId === 'todos') {
    return [];
  }

  try {
    const { data, error } = await supabase
      .from('moradores')
      .select('*')
      .eq('condominio_id', condominioId)
      .order('unidade', { ascending: true });

    if (!error && data && Array.isArray(data)) {
      try {
        localStorage.setItem(`porttohub_cache_moradores_${condominioId}`, JSON.stringify(data));
      } catch {}
      return data as MoradorBaseInfo[];
    }
  } catch (err) {
    console.warn('[ControleAcesso] Erro ao buscar moradores base do Supabase:', err);
  }

  try {
    const cached = localStorage.getItem(`porttohub_cache_moradores_${condominioId}`);
    if (cached) {
      const parsed = JSON.parse(cached);
      if (Array.isArray(parsed) && parsed.length > 0) {
        return parsed as MoradorBaseInfo[];
      }
    }
  } catch {}

  return [];
}

export function extrairUnidadesBase(
  condoConfig?: any,
  moradores?: MoradorBaseInfo[]
): string[] {
  const setUnidades = new Set<string>();

  if (moradores && Array.isArray(moradores)) {
    moradores.forEach(m => {
      if (m.unidade) {
        const rotulo = m.bloco ? `${m.bloco} - Apto ${m.unidade}` : `Apto ${m.unidade}`;
        setUnidades.add(rotulo);
        setUnidades.add(m.unidade);
      }
    });
  }

  if (condoConfig?.blocos_detalhes && Array.isArray(condoConfig.blocos_detalhes)) {
    condoConfig.blocos_detalhes.forEach((bloco: any) => {
      const nomeBloco = bloco.nome || 'Bloco A';
      if (bloco.estrutura?.unidadesCustomizadas && Array.isArray(bloco.estrutura.unidadesCustomizadas)) {
        bloco.estrutura.unidadesCustomizadas.forEach((u: string) => {
          setUnidades.add(`${nomeBloco} - Apto ${u}`);
          setUnidades.add(u);
        });
      } else {
        const qtd = bloco.unidades || 20;
        for (let i = 1; i <= Math.min(qtd, 40); i++) {
          setUnidades.add(`${nomeBloco} - Apto ${i}`);
        }
      }
    });
  }

  if (condoConfig?.unidades_customizadas && Array.isArray(condoConfig.unidades_customizadas)) {
    condoConfig.unidades_customizadas.forEach((u: string) => setUnidades.add(u));
  }

  return Array.from(setUnidades).sort();
}

export function buscarMoradorPorPlaca(placa: string, moradores: MoradorBaseInfo[]): MoradorBaseInfo | null {
  if (!placa || !moradores) return null;
  const pLimpa = placa.replace(/[^a-zA-Z0-9]/g, '').toUpperCase();
  if (pLimpa.length < 3) return null;

  return moradores.find(m => {
    if (!m.veiculo_placa) return false;
    const pMorador = m.veiculo_placa.replace(/[^a-zA-Z0-9]/g, '').toUpperCase();
    return pMorador === pLimpa;
  }) || null;
}

export function buscarMoradoresPorUnidade(unidadeStr: string, moradores: MoradorBaseInfo[]): MoradorBaseInfo[] {
  if (!unidadeStr || !moradores) return [];
  const uLimpa = unidadeStr.toLowerCase().replace(/[^a-z0-9]/g, '');

  return moradores.filter(m => {
    if (!m.unidade) return false;
    const mUnidadeLimpa = m.unidade.toLowerCase().replace(/[^a-z0-9]/g, '');
    const mCompletoLimpo = `${m.bloco || ''}${m.unidade}`.toLowerCase().replace(/[^a-z0-9]/g, '');
    return mUnidadeLimpa === uLimpa || mCompletoLimpo.includes(uLimpa) || uLimpa.includes(mUnidadeLimpa);
  });
}

export async function alternarStatusAcessoMorador(
  moradorId: string,
  novoStatus: 'liberado' | 'bloqueado',
  condominioId: string
): Promise<{ sucesso: boolean; sincronizado?: boolean; erro?: string }> {
  if (!isUUID(condominioId) || !isUUID(moradorId)) {
    return { sucesso: false, erro: 'Identificador de morador ou condomínio inválido.' };
  }

  let sincronizado = false;
  if (typeof navigator !== 'undefined' && !navigator.onLine) {
    enfileirarAcaoOffline(
      'moradores',
      'UPDATE',
      { id: moradorId, condominio_id: condominioId, status_acesso: novoStatus },
      `Status acesso morador (${novoStatus})`
    );
  } else {
    try {
      const { error } = await supabase
        .from('moradores')
        .update({ status_acesso: novoStatus })
        .eq('id', moradorId)
        .eq('condominio_id', condominioId);

      if (error) {
        if (ehErroDeRedeOuOffline(error)) {
          enfileirarAcaoOffline(
            'moradores',
            'UPDATE',
            { id: moradorId, condominio_id: condominioId, status_acesso: novoStatus },
            `Status acesso morador (${novoStatus})`
          );
        } else {
          return {
            sucesso: false,
            erro: formatarErroDetalhadoSupabase(error, 'Erro ao atualizar status do morador')
          };
        }
      } else {
        sincronizado = true;
      }
    } catch (err: any) {
      if (ehErroDeRedeOuOffline(err)) {
        enfileirarAcaoOffline(
          'moradores',
          'UPDATE',
          { id: moradorId, condominio_id: condominioId, status_acesso: novoStatus },
          `Status acesso morador (${novoStatus})`
        );
      } else {
        return {
          sucesso: false,
          erro: formatarErroDetalhadoSupabase(err, 'Erro inesperado ao atualizar status do morador')
        };
      }
    }
  }

  try {
    const cached = localStorage.getItem(`porttohub_cache_moradores_${condominioId}`);
    if (cached) {
      const parsed: MoradorBaseInfo[] = JSON.parse(cached);
      const atualizados = parsed.map(m => m.id === moradorId ? { ...m, status_acesso: novoStatus } : m);
      localStorage.setItem(`porttohub_cache_moradores_${condominioId}`, JSON.stringify(atualizados));
    }
  } catch {}

  return { sucesso: true, sincronizado };
}
