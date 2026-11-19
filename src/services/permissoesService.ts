import { supabase, formatarErroDetalhadoSupabase } from './supabase';
import { isUUID } from './condominioService';
import { normalizarPerfilOperador, temAcessoGlobalExplicito } from './autorizacaoService';
import { invalidarCacheTabela } from './redisCacheService';

export interface PermissaoModuloPadrao {
  visualizar?: boolean;
  criar?: boolean;
  editar?: boolean;
  excluir?: boolean;
  [key: string]: boolean | undefined;
}

export interface PermissoesModulo {
  encomendas?: PermissaoModuloPadrao & {
    entrada_lote?: boolean;
    cadastrar_entregador?: boolean;
    triagem?: boolean;
    baixa?: boolean;
    editar_pacote?: boolean;
    excluir_pacote?: boolean;
    dossie?: boolean;
    editar_lotes?: boolean;
    excluir_lotes?: boolean;
    historico?: boolean;
  };
  custodia?: PermissaoModuloPadrao & {
    receber?: boolean;
    baixa?: boolean;
    auditoria?: boolean;
  };
  chaves?: PermissaoModuloPadrao & {
    emprestar?: boolean;
    devolver?: boolean;
    cadastrar?: boolean;
    excluir?: boolean;
  };
  rondas?: PermissaoModuloPadrao & {
    iniciar_ronda?: boolean;
    cadastrar_pontos?: boolean;
    setores?: boolean;
  };
  autorizados?: PermissaoModuloPadrao & {
    cadastrar?: boolean;
    dar_entrada?: boolean;
    dar_saida?: boolean;
  };
  materiais?: PermissaoModuloPadrao & {
    cadastrar_equipamentos?: boolean;
    alterar_status?: boolean;
    editar?: boolean;
    excluir?: boolean;
  };
  manutencao?: PermissaoModuloPadrao & {
    abrir_os?: boolean;
    concluir?: boolean;
    excluir?: boolean;
  };
  ocorrencias?: PermissaoModuloPadrao & {
    criar?: boolean;
    resolver?: boolean;
    excluir?: boolean;
  };
  passagem_posto?: PermissaoModuloPadrao & {
    assumir_posto?: boolean;
    relatorio?: boolean;
  };
  cadastros?: PermissaoModuloPadrao & {
    visualizar_moradores?: boolean;
    moradores?: boolean;
    cadastrar_morador?: boolean;
    editar_morador?: boolean;
    excluir_morador?: boolean;
    gerenciar_veiculos?: boolean;
    vincular_tags?: boolean;
    status_acesso_morador?: boolean;
    exportar_moradores?: boolean;
    visualizar_operadores?: boolean;
    operadores?: boolean;
    editar_operadores?: boolean;
    alterar_senha_operador?: boolean;
    excluir_operadores?: boolean;
    gerenciar_niveis?: boolean;
    configurar_condominio?: boolean;
    condominios?: boolean;
    excluir?: boolean;
  };
  moradores?: PermissaoModuloPadrao & {
    adicionar?: boolean;
    editar?: boolean;
    excluir?: boolean;
  };
  historico_absoluto?: PermissaoModuloPadrao & {
    ver_feed?: boolean;
    ver_metricas?: boolean;
    exportar_csv?: boolean;
    limpar_dados?: boolean;
  };
  configuracoes?: PermissaoModuloPadrao & {
    gerenciar_niveis?: boolean;
    feature_flags?: boolean;
  };
  bancada?: PermissaoModuloPadrao & {
    lancar?: boolean;
    baixa?: boolean;
    zerar?: boolean;
    historico?: boolean;
  };
  reservas?: PermissaoModuloPadrao & {
    aprovar?: boolean;
    cancelar?: boolean;
    gerenciar_areas?: boolean;
    vistoria?: boolean;
  };
  controle_acesso?: PermissaoModuloPadrao & {
    liberar_entrada?: boolean;
    registrar_saida?: boolean;
    bloquear?: boolean;
    gerar_passe_qr?: boolean;
    configurar_portoes?: boolean;
  };
  painel_sindico?: PermissaoModuloPadrao & {
    relatorio?: boolean;
    auditoria?: boolean;
    nova_ocorrencia?: boolean;
    nova_os?: boolean;
  };
}

export interface NivelAcessoItem {
  id: string; // Ex: 'nivel_0', 'nivel_1', 'nivel_2', 'nivel_3', 'nivel_4', ou custom
  nome: string; // Ex: 'Nível 0 — Administrador Geral', 'Supervisor de Segurança', etc.
  descricao?: string;
  condominio_id?: string | null;
  padrao_sistema?: boolean; // Se é nível nativo do sistema
  permissoes: PermissoesModulo;
}

export interface ModuloAcaoInfo {
  id: string;
  label: string;
}

export interface ModuloDefinicaoInfo {
  id: keyof PermissoesModulo;
  nome: string;
  descricao?: string;
  acoesEspecificas: ModuloAcaoInfo[];
}

export const MODULOS_DEFINICAO_RBAC: ModuloDefinicaoInfo[] = [
  {
    id: 'painel_sindico',
    nome: 'Portal do Síndico & Auditoria',
    acoesEspecificas: [
      { id: 'relatorio', label: 'Exportar Relatórios Executivos' },
      { id: 'nova_ocorrencia', label: 'Registrar Ocorrência pelo Síndico' },
      { id: 'nova_os', label: 'Abrir Chamado OS pelo Síndico' }
    ]
  },
  {
    id: 'encomendas',
    nome: 'Encomendas',
    acoesEspecificas: [
      { id: 'entrada_lote', label: '1ª Etapa: Recebimento de Lotes' },
      { id: 'criar_lote', label: 'Adicionar Novo Lote' },
      { id: 'cadastrar_entregador', label: 'Cadastrar Novo Entregador' },
      { id: 'triagem', label: '2ª Etapa: Efetuar Triagem' },
      { id: 'baixa', label: '3ª Etapa: Dar Saída / Baixa' },
      { id: 'editar_pacote', label: 'Editar Pacote Retido' },
      { id: 'excluir_pacote', label: 'Excluir Pacote Retido' },
      { id: 'dossie', label: 'Auditoria & Provas: Aba Dossiê' },
      { id: 'editar_lotes', label: 'Editar Lotes de Encomendas' },
      { id: 'excluir_lotes', label: 'Excluir Lotes de Encomendas' }
    ]
  },
  {
    id: 'custodia',
    nome: 'Custódia de Itens',
    acoesEspecificas: [
      { id: 'receber', label: 'Receber e Guardar' },
      { id: 'baixa', label: 'Baixa / Devolução' },
      { id: 'editar', label: 'Editar Item Guardado' },
      { id: 'excluir', label: 'Excluir Registro de Custódia' },
      { id: 'auditoria', label: 'Auditoria' }
    ]
  },
  {
    id: 'chaves',
    nome: 'Quadro Digital de Chaves (Claviculário)',
    acoesEspecificas: [
      { id: 'emprestar', label: 'Emprestar Chave' },
      { id: 'devolver', label: 'Devolver Chave' },
      { id: 'cadastrar', label: 'Cadastrar / Editar Chave' },
      { id: 'excluir', label: 'Excluir Chave do Quadro' }
    ]
  },
  {
    id: 'rondas',
    nome: 'Rondas Patrimoniais QR',
    acoesEspecificas: [
      { id: 'iniciar_ronda', label: 'Iniciar Ronda' },
      { id: 'cadastrar_pontos', label: 'Cadastrar / Editar Pontos' },
      { id: 'setores', label: 'Configurar Setores' }
    ]
  },
  {
    id: 'autorizados',
    nome: 'Autorizados & Prestadores',
    acoesEspecificas: [
      { id: 'cadastrar', label: 'Cadastrar / Liberar' },
      { id: 'dar_entrada', label: 'Dar Entrada' },
      { id: 'dar_saida', label: 'Dar Saída' }
    ]
  },
  {
    id: 'materiais',
    nome: 'Materiais & Inventário do Posto',
    acoesEspecificas: [
      { id: 'cadastrar_equipamentos', label: 'Cadastrar Novos Equipamentos' },
      { id: 'alterar_status', label: 'Alterar Status / Apontar Avaria c/ Foto' },
      { id: 'editar', label: 'Editar Dados Cadastrais / Patrimônio' },
      { id: 'excluir', label: 'Excluir / Baixar Equipamento' }
    ]
  },
  {
    id: 'manutencao',
    nome: 'Gestão de Manutenção & OS',
    acoesEspecificas: [
      { id: 'abrir_os', label: 'Abertura de Chamados (OS)' },
      { id: 'concluir', label: 'Resolução / Concluir OS' },
      { id: 'excluir', label: 'Excluir Chamado' }
    ]
  },
  {
    id: 'ocorrencias',
    nome: 'Livro de Ocorrências',
    acoesEspecificas: [
      { id: 'criar', label: 'Registrar c/ áudio/foto' },
      { id: 'resolver', label: 'Dar Ciência / Resolver' },
      { id: 'excluir', label: 'Excluir Ocorrência' }
    ]
  },
  {
    id: 'passagem_posto',
    nome: 'Passagem de Posto',
    acoesEspecificas: [
      { id: 'assumir_posto', label: 'Realizar / Assumir Passagem' },
      { id: 'relatorio', label: 'Ver Relatório Completo' }
    ]
  },
  {
    id: 'cadastros',
    nome: 'Cadastros Base',
    descricao: 'Gestão completa de condomínios, postos, operadores, moradores, veículos e tags RFID',
    acoesEspecificas: [
      { id: 'visualizar_moradores', label: 'Visualizar Moradores & Unidades (Consulta)' },
      { id: 'cadastrar_morador', label: 'Cadastrar Novos Moradores' },
      { id: 'editar_morador', label: 'Editar Dados de Moradores' },
      { id: 'excluir_morador', label: 'Excluir Moradores / Dependentes' },
      { id: 'gerenciar_veiculos', label: 'Cadastrar e Editar Veículos & Placas' },
      { id: 'vincular_tags', label: 'Vincular / Alterar Tags RFID' },
      { id: 'status_acesso_morador', label: 'Alterar Status de Acesso (Bloquear / Liberar)' },
      { id: 'exportar_moradores', label: 'Exportar Lista de Moradores (CSV / Relatórios)' },
      { id: 'visualizar_operadores', label: 'Visualizar Equipe de Operadores' },
      { id: 'operadores', label: 'Cadastrar Novos Operadores' },
      { id: 'editar_operadores', label: 'Editar Operadores Existentes' },
      { id: 'alterar_senha_operador', label: 'Redefinir Senhas de Operadores' },
      { id: 'excluir_operadores', label: 'Excluir ou Desativar Operadores' },
      { id: 'gerenciar_niveis', label: 'Gerenciar Permissões Granulares & Níveis (RBAC)' },
      { id: 'configurar_condominio', label: 'Configurar Condomínio / Posto' },
      { id: 'condominios', label: 'Cadastrar Novos Condomínios (Multi-Condomínio)' },
      { id: 'excluir', label: 'Exclusão Geral de Registros em Cadastros' }
    ]
  },
  {
    id: 'historico_absoluto',
    nome: 'Histórico Absoluto & Auditoria',
    acoesEspecificas: [
      { id: 'visualizar', label: 'Visualização do Histórico Absoluto' },
      { id: 'ver_feed', label: 'Feed em Tempo Real' },
      { id: 'ver_metricas', label: 'Métricas & Indicadores' },
      { id: 'exportar_csv', label: 'Exportar Relatórios CSV' },
      { id: 'limpar_dados', label: 'Exclusão de Dados por Período (Limpar Dados - Apenas ADM)' }
    ]
  },
  {
    id: 'configuracoes',
    nome: 'Configurações do Sistema',
    acoesEspecificas: [
      { id: 'gerenciar_niveis', label: 'Gerenciar Níveis (RBAC)' },
      { id: 'feature_flags', label: 'Feature Flags (Módulos)' }
    ]
  },
  {
    id: 'bancada',
    nome: 'Bancada (Balcão Físico)',
    acoesEspecificas: [
      { id: 'lancar', label: 'Lançar Unidades na Bancada' },
      { id: 'baixa', label: 'Dar Baixa / Entregar Volumes' },
      { id: 'zerar', label: 'Zerar / Nova Conferência' },
      { id: 'historico', label: 'Ver Histórico de Auditoria' }
    ]
  },
  {
    id: 'reservas',
    nome: 'Reserva de Áreas Comuns',
    acoesEspecificas: [
      { id: 'criar', label: 'Solicitar / Criar Reserva' },
      { id: 'aprovar', label: 'Aprovar ou Recusar Reservas' },
      { id: 'cancelar', label: 'Cancelar Reserva' },
      { id: 'gerenciar_areas', label: 'Cadastrar / Configurar Espaços' },
      { id: 'vistoria', label: 'Vistoria Pré/Pós Evento' }
    ]
  },
  {
    id: 'controle_acesso',
    nome: 'Controle de Acesso & Portaria',
    acoesEspecificas: [
      { id: 'liberar_entrada', label: 'Liberar Entrada (Pedestres / Veículos)' },
      { id: 'registrar_saida', label: 'Registrar Saída do Posto' },
      { id: 'bloquear', label: 'Gerenciar Blacklist / Bloqueios' },
      { id: 'gerar_passe_qr', label: 'Gerar Convite / Passe Virtual QR' },
      { id: 'configurar_portoes', label: 'Configurar Pontos de Acesso / Cancelas' }
    ]
  }
];

export const NIVEIS_PADRAO: NivelAcessoItem[] = [
  {
    id: 'nivel_0',
    nome: 'Nível 0 — Administrador Geral',
    descricao: 'Acesso total e irrestrito a todos os módulos, configurações, exclusões e expurgo de dados.',
    condominio_id: null,
    padrao_sistema: true,
    permissoes: {
      encomendas: { visualizar: true, criar: true, editar: true, excluir: true, entrada_lote: true, triagem: true, baixa: true, dossie: true, editar_lotes: true, excluir_lotes: true, cadastrar_entregador: true, editar_pacote: true, excluir_pacote: true, historico: true },
      custodia: { visualizar: true, criar: true, editar: true, excluir: true, receber: true, baixa: true, auditoria: true },
      chaves: { visualizar: true, criar: true, editar: true, excluir: true, emprestar: true, devolver: true, cadastrar: true },
      rondas: { visualizar: true, criar: true, editar: true, excluir: true, iniciar_ronda: true, cadastrar_pontos: true, setores: true },
      autorizados: { visualizar: true, criar: true, editar: true, excluir: true, cadastrar: true, dar_entrada: true, dar_saida: true },
      materiais: { visualizar: true, criar: true, editar: true, excluir: true, cadastrar_equipamentos: true, alterar_status: true },
      manutencao: { visualizar: true, criar: true, editar: true, excluir: true, abrir_os: true, concluir: true },
      ocorrencias: { visualizar: true, criar: true, editar: true, excluir: true, resolver: true },
      passagem_posto: { visualizar: true, criar: true, editar: true, excluir: true, assumir_posto: true, relatorio: true },
      cadastros: { visualizar: true, criar: true, editar: true, excluir: true, moradores: true, visualizar_moradores: true, cadastrar_morador: true, editar_morador: true, excluir_morador: true, gerenciar_veiculos: true, vincular_tags: true, status_acesso_morador: true, exportar_moradores: true, visualizar_operadores: true, operadores: true, editar_operadores: true, alterar_senha_operador: true, excluir_operadores: true, configurar_condominio: true, condominios: true, gerenciar_niveis: true },
      moradores: { visualizar: true, criar: true, editar: true, excluir: true, adicionar: true },
      historico_absoluto: { visualizar: true, criar: true, editar: true, excluir: true, ver_feed: true, ver_metricas: true, exportar_csv: true, limpar_dados: true },
      configuracoes: { visualizar: true, criar: true, editar: true, excluir: true, gerenciar_niveis: true, feature_flags: true },
      bancada: { visualizar: true, criar: true, editar: true, excluir: true, lancar: true, baixa: true, zerar: true, historico: true },
      reservas: { visualizar: true, criar: true, editar: true, excluir: true, aprovar: true, cancelar: true, gerenciar_areas: true, vistoria: true },
      controle_acesso: { visualizar: true, criar: true, editar: true, excluir: true, liberar_entrada: true, registrar_saida: true, bloquear: true, gerar_passe_qr: true, configurar_portoes: true }
    }
  },
  {
    id: 'nivel_1',
    nome: 'Nível 1 — Administrador de Condomínio',
    descricao: 'Gestão completa do próprio condomínio, moradores, cadastros e equipe local (sem acesso global).',
    condominio_id: null,
    padrao_sistema: true,
    permissoes: {
      encomendas: { visualizar: true, criar: true, editar: true, excluir: true, entrada_lote: true, triagem: true, baixa: true, dossie: true, editar_lotes: true, excluir_lotes: true, cadastrar_entregador: true, editar_pacote: true, excluir_pacote: true, historico: true },
      custodia: { visualizar: true, criar: true, editar: true, excluir: false, receber: true, baixa: true, auditoria: true },
      chaves: { visualizar: true, criar: true, editar: true, excluir: false, emprestar: true, devolver: true, cadastrar: true },
      rondas: { visualizar: true, criar: true, editar: true, excluir: false, iniciar_ronda: true, cadastrar_pontos: true, setores: true },
      autorizados: { visualizar: true, criar: true, editar: true, excluir: false, cadastrar: true, dar_entrada: true, dar_saida: true },
      materiais: { visualizar: true, criar: true, editar: true, excluir: false, cadastrar_equipamentos: true, alterar_status: true },
      manutencao: { visualizar: true, criar: true, editar: true, excluir: false, abrir_os: true, concluir: true },
      ocorrencias: { visualizar: true, criar: true, editar: true, excluir: false, resolver: true },
      passagem_posto: { visualizar: true, criar: true, editar: true, excluir: false, assumir_posto: true, relatorio: true },
      cadastros: { visualizar: true, criar: true, editar: true, excluir: false, moradores: true, visualizar_moradores: true, cadastrar_morador: true, editar_morador: true, excluir_morador: false, gerenciar_veiculos: true, vincular_tags: true, status_acesso_morador: true, exportar_moradores: true, visualizar_operadores: true, operadores: true, editar_operadores: true, alterar_senha_operador: true, excluir_operadores: false, configurar_condominio: true, condominios: false, gerenciar_niveis: false },
      moradores: { visualizar: true, criar: true, editar: true, excluir: false, adicionar: true },
      historico_absoluto: { visualizar: true, criar: false, editar: false, excluir: false, ver_feed: true, ver_metricas: true, exportar_csv: true, limpar_dados: false },
      configuracoes: { visualizar: false, criar: false, editar: false, excluir: false, gerenciar_niveis: false, feature_flags: false },
      bancada: { visualizar: true, criar: true, editar: true, excluir: false, lancar: true, baixa: true, zerar: true, historico: true },
      reservas: { visualizar: true, criar: true, editar: true, excluir: false, aprovar: true, cancelar: true, gerenciar_areas: true, vistoria: true },
      controle_acesso: { visualizar: true, criar: true, editar: true, excluir: false, liberar_entrada: true, registrar_saida: true, bloquear: true, gerar_passe_qr: true, configurar_portoes: true }
    }
  },
  {
    id: 'nivel_2',
    nome: 'Nível 2 — Supervisor de Segurança',
    descricao: 'Supervisão operacional de equipes nos condomínios vinculados, rondas, ocorrências e portaria (sem poderes administrativos de usuários).',
    condominio_id: null,
    padrao_sistema: true,
    permissoes: {
      encomendas: { visualizar: true, criar: true, editar: true, excluir: true, entrada_lote: true, triagem: true, baixa: true, dossie: true, editar_lotes: true, excluir_lotes: true, cadastrar_entregador: true, editar_pacote: true, excluir_pacote: true, historico: true },
      custodia: { visualizar: true, criar: true, editar: false, excluir: false, receber: true, baixa: true, auditoria: true },
      chaves: { visualizar: true, criar: true, editar: true, excluir: false, emprestar: true, devolver: true, cadastrar: true },
      rondas: { visualizar: true, criar: true, editar: true, excluir: false, iniciar_ronda: true, cadastrar_pontos: true, setores: false },
      autorizados: { visualizar: true, criar: true, editar: true, excluir: false, cadastrar: true, dar_entrada: true, dar_saida: true },
      materiais: { visualizar: true, criar: true, editar: true, excluir: false, cadastrar_equipamentos: true, alterar_status: true },
      manutencao: { visualizar: true, criar: true, editar: true, excluir: false, abrir_os: true, concluir: true },
      ocorrencias: { visualizar: true, criar: true, editar: true, excluir: false, resolver: true },
      passagem_posto: { visualizar: true, criar: true, editar: true, excluir: false, assumir_posto: true, relatorio: true },
      cadastros: { visualizar: true, criar: true, editar: true, excluir: false, moradores: true, visualizar_moradores: true, cadastrar_morador: true, editar_morador: true, excluir_morador: false, gerenciar_veiculos: true, vincular_tags: true, status_acesso_morador: true, exportar_moradores: true, visualizar_operadores: true, operadores: false, editar_operadores: false, alterar_senha_operador: false, excluir_operadores: false, configurar_condominio: false, condominios: false, gerenciar_niveis: false },
      moradores: { visualizar: true, criar: true, editar: true, excluir: false, adicionar: true },
      historico_absoluto: { visualizar: true, criar: false, editar: false, excluir: false, ver_feed: true, ver_metricas: true, exportar_csv: false, limpar_dados: false },
      configuracoes: { visualizar: false, criar: false, editar: false, excluir: false, gerenciar_niveis: false, feature_flags: false },
      bancada: { visualizar: true, criar: true, editar: true, excluir: false, lancar: true, baixa: true, zerar: false, historico: true },
      reservas: { visualizar: true, criar: true, editar: true, excluir: false, aprovar: true, cancelar: true, gerenciar_areas: false, vistoria: true },
      controle_acesso: { visualizar: true, criar: true, editar: true, excluir: false, liberar_entrada: true, registrar_saida: true, bloquear: true, gerar_passe_qr: true, configurar_portoes: false }
    }
  },
  {
    id: 'nivel_3',
    nome: 'Nível 3 — Operador de Guarita / Portaria',
    descricao: 'Operação cotidiana do posto de trabalho: encomendas, triagem, liberação de pessoas e chaves.',
    condominio_id: null,
    padrao_sistema: true,
    permissoes: {
      encomendas: { visualizar: true, criar: true, editar: false, excluir: false, entrada_lote: true, triagem: true, baixa: true, dossie: false, editar_lotes: false, excluir_lotes: false, cadastrar_entregador: true, editar_pacote: false, excluir_pacote: false, historico: true },
      custodia: { visualizar: true, criar: true, editar: false, excluir: false, receber: true, baixa: true, auditoria: false },
      chaves: { visualizar: true, criar: true, editar: false, excluir: false, emprestar: true, devolver: true, cadastrar: false },
      rondas: { visualizar: true, criar: true, editar: false, excluir: false, iniciar_ronda: true, cadastrar_pontos: false, setores: false },
      autorizados: { visualizar: true, criar: true, editar: false, excluir: false, cadastrar: true, dar_entrada: true, dar_saida: true },
      materiais: { visualizar: true, criar: false, editar: false, excluir: false, cadastrar_equipamentos: false, alterar_status: true },
      manutencao: { visualizar: true, criar: true, editar: false, excluir: false, abrir_os: true, concluir: false },
      ocorrencias: { visualizar: true, criar: true, editar: false, excluir: false, resolver: false },
      passagem_posto: { visualizar: true, criar: true, editar: true, excluir: false, assumir_posto: true, relatorio: true },
      cadastros: { visualizar: true, criar: false, editar: false, excluir: false, moradores: false, visualizar_moradores: true, cadastrar_morador: true, editar_morador: false, excluir_morador: false, gerenciar_veiculos: true, vincular_tags: false, status_acesso_morador: false, exportar_moradores: false, visualizar_operadores: false, operadores: false, editar_operadores: false, alterar_senha_operador: false, excluir_operadores: false, configurar_condominio: false, condominios: false, gerenciar_niveis: false },
      moradores: { visualizar: true, criar: true, editar: false, excluir: false, adicionar: true },
      historico_absoluto: { visualizar: true, criar: false, editar: false, excluir: false, ver_feed: true, ver_metricas: false, exportar_csv: false, limpar_dados: false },
      configuracoes: { visualizar: false, criar: false, editar: false, excluir: false, gerenciar_niveis: false, feature_flags: false },
      bancada: { visualizar: true, criar: true, editar: false, excluir: false, lancar: true, baixa: true, zerar: false, historico: false },
      reservas: { visualizar: true, criar: true, editar: false, excluir: false, aprovar: false, cancelar: false, gerenciar_areas: false, vistoria: true },
      controle_acesso: { visualizar: true, criar: true, editar: true, excluir: false, liberar_entrada: true, registrar_saida: true, bloquear: false, gerar_passe_qr: true, configurar_portoes: false }
    }
  },
  {
    id: 'nivel_4',
    nome: 'Nível 4 — Síndico (Visualização & Consultas)',
    descricao: 'Acesso de consulta executiva a dashboards, relatórios e dossiês sem edição de portaria.',
    condominio_id: null,
    padrao_sistema: true,
    permissoes: {
      encomendas: { visualizar: true, criar: false, editar: false, excluir: false, entrada_lote: false, triagem: false, baixa: false, dossie: true, editar_lotes: false, excluir_lotes: false, cadastrar_entregador: false, editar_pacote: false, excluir_pacote: false, historico: true },
      custodia: { visualizar: true, criar: false, editar: false, excluir: false, receber: false, baixa: false, auditoria: true },
      chaves: { visualizar: true, criar: false, editar: false, excluir: false, emprestar: false, devolver: false, cadastrar: false },
      rondas: { visualizar: true, criar: false, editar: false, excluir: false, iniciar_ronda: false, cadastrar_pontos: false, setores: false },
      autorizados: { visualizar: true, criar: false, editar: false, excluir: false, cadastrar: false, dar_entrada: false, dar_saida: false },
      materiais: { visualizar: true, criar: false, editar: false, excluir: false, cadastrar_equipamentos: false, alterar_status: false },
      bancada: { visualizar: true, criar: false, editar: false, excluir: false, lancar: false, baixa: false, zerar: false, historico: true },
      manutencao: { visualizar: true, criar: true, editar: false, excluir: false, abrir_os: true, concluir: false },
      ocorrencias: { visualizar: true, criar: true, editar: false, excluir: false, resolver: true },
      passagem_posto: { visualizar: true, criar: false, editar: false, excluir: false, assumir_posto: false, relatorio: true },
      cadastros: { visualizar: true, criar: false, editar: false, excluir: false, moradores: false, visualizar_moradores: true, cadastrar_morador: false, editar_morador: false, excluir_morador: false, gerenciar_veiculos: false, vincular_tags: false, status_acesso_morador: false, exportar_moradores: true, visualizar_operadores: true, operadores: false, editar_operadores: false, alterar_senha_operador: false, excluir_operadores: false, configurar_condominio: false, condominios: false, gerenciar_niveis: false },
      moradores: { visualizar: true, criar: false, editar: false, excluir: false, adicionar: false },
      historico_absoluto: { visualizar: true, criar: false, editar: false, excluir: false, ver_feed: true, ver_metricas: true, exportar_csv: true, limpar_dados: false },
      configuracoes: { visualizar: false, criar: false, editar: false, excluir: false, gerenciar_niveis: false, feature_flags: false },
      reservas: { visualizar: true, criar: true, editar: true, excluir: false, aprovar: true, cancelar: true, gerenciar_areas: true, vistoria: true },
      controle_acesso: { visualizar: true, criar: false, editar: false, excluir: false, liberar_entrada: false, registrar_saida: false, bloquear: true, gerar_passe_qr: false, configurar_portoes: false }
    }
  }
];

const STORAGE_KEY_NIVEIS = 'infport_niveis_acesso_v1';
let cacheNiveisMemoria: NivelAcessoItem[] | null = null;

export function obterNiveisLocal(): NivelAcessoItem[] {
  if (cacheNiveisMemoria && Array.isArray(cacheNiveisMemoria) && cacheNiveisMemoria.length > 0) {
    return cacheNiveisMemoria;
  }

  try {
    const raw = localStorage.getItem(STORAGE_KEY_NIVEIS);
    if (raw) {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed) && parsed.length > 0) {
        // Garantir que todos os níveis padrão existam e suas permissões sofram merge profundo
        const mapa = new Map<string, NivelAcessoItem>();
        NIVEIS_PADRAO.forEach(n => mapa.set(n.id, JSON.parse(JSON.stringify(n))));
        parsed.forEach((n: NivelAcessoItem) => {
          const padrao = mapa.get(n.id);
          if (padrao) {
            mapa.set(n.id, {
              ...padrao,
              ...n,
              permissoes: {
                ...padrao.permissoes,
                ...(n.permissoes || {})
              }
            });
          } else {
            mapa.set(n.id, n);
          }
        });
        const consolidados = Array.from(mapa.values());
        cacheNiveisMemoria = consolidados;
        return consolidados;
      }
    }
  } catch (e) {
    console.warn('Erro ao ler níveis locais:', e);
  }
  cacheNiveisMemoria = [...NIVEIS_PADRAO];
  return [...NIVEIS_PADRAO];
}

export function salvarNiveisLocal(niveis: NivelAcessoItem[]) {
  cacheNiveisMemoria = niveis;
  try {
    localStorage.setItem(STORAGE_KEY_NIVEIS, JSON.stringify(niveis));
  } catch (e) {
    console.warn('Erro ao salvar níveis locais:', e);
  }
  // Notifica imediatamente toda a aplicação para reavaliação de permissões
  try {
    window.dispatchEvent(new CustomEvent('niveis_acesso_atualizados', { detail: niveis }));
  } catch (e) {
    // ignore
  }
}

export function limparCacheNiveisAcesso(): void {
  cacheNiveisMemoria = null;
  try {
    if (typeof localStorage !== 'undefined') {
      localStorage.removeItem(STORAGE_KEY_NIVEIS);
    }
  } catch {
    // ignore
  }
}

export async function carregarNiveisAcesso(condominioId?: string): Promise<NivelAcessoItem[]> {
  const locais = obterNiveisLocal();

  try {
    let targetCondo = condominioId;
    if (!targetCondo || targetCondo === 'global' || targetCondo === 'todos' || !isUUID(targetCondo)) {
      const { data: c } = await supabase.from('condominios').select('id').limit(1).maybeSingle();
      if (c?.id && isUUID(c.id)) targetCondo = c.id;
      else targetCondo = undefined;
    }

    if (targetCondo && isUUID(targetCondo)) {
      const { data, error } = await supabase
        .from('configuracoes')
        .select('niveis_acesso')
        .eq('condominio_id', targetCondo)
        .maybeSingle();

      if (!error && Array.isArray(data?.niveis_acesso)) {
        // Fonte única: mescla somente NIVEIS_PADRAO + configuracoes.niveis_acesso do condomínio alvo
        // (nunca preserva níveis personalizados antigos ou de outro condomínio em localStorage)
        const mapa = new Map<string, NivelAcessoItem>();
        NIVEIS_PADRAO.forEach(n => mapa.set(n.id, JSON.parse(JSON.stringify(n))));
        data.niveis_acesso.forEach((n: NivelAcessoItem) => {
          if (!n || !n.id) return;
          const padrao = mapa.get(n.id);
          if (padrao) {
            mapa.set(n.id, { ...padrao, ...n, permissoes: { ...padrao.permissoes, ...(n.permissoes || {}) } });
          } else {
            mapa.set(n.id, n);
          }
        });
        const consolidados = Array.from(mapa.values());
        salvarNiveisLocal(consolidados);
        return consolidados;
      }
    }
  } catch (err) {
    console.warn('Erro ao buscar níveis remotos:', err);
  }

  return locais;
}

export async function salvarNivelAcesso(nivel: NivelAcessoItem, condominioId?: string): Promise<void> {
  const atuais = obterNiveisLocal();
  let targetCondo = condominioId || nivel.condominio_id;
  if (!targetCondo || targetCondo === 'global' || targetCondo === 'todos' || !isUUID(targetCondo)) {
    const { data: c } = await supabase.from('condominios').select('id').limit(1).maybeSingle();
    if (c?.id && isUUID(c.id)) targetCondo = c.id;
    else targetCondo = undefined;
  }

  if (!targetCondo || !isUUID(targetCondo)) {
    throw new Error('Selecione um condomínio válido antes de salvar níveis de acesso no servidor.');
  }

  if (typeof navigator !== 'undefined' && navigator.onLine === false) {
    throw new Error('Alteração de níveis de acesso exige conexão ativa com o servidor.');
  }

  const nivelParaSalvar: NivelAcessoItem = {
    ...nivel,
    condominio_id: targetCondo
  };

  const idx = atuais.findIndex(n => n.id === nivel.id);
  const atualizados: NivelAcessoItem[] = idx >= 0
    ? atuais.map((item, i) => (i === idx ? nivelParaSalvar : item))
    : [...atuais, nivelParaSalvar];

  const { error: upsertErr } = await supabase
    .from('configuracoes')
    .upsert({
      condominio_id: targetCondo,
      niveis_acesso: atualizados
    } as any, { onConflict: 'condominio_id' });

  if (upsertErr) {
    if (upsertErr.code === '42501' || (upsertErr.message || '').toLowerCase().includes('row-level security')) {
      throw new Error(formatarErroDetalhadoSupabase(upsertErr, 'Permissão negada para salvar níveis de acesso'));
    }
    const { error: updErr } = await supabase
      .from('configuracoes')
      .update({ niveis_acesso: atualizados } as any)
      .eq('condominio_id', targetCondo);
    if (updErr) {
      throw new Error(formatarErroDetalhadoSupabase(updErr, 'Falha ao salvar níveis de acesso no Supabase'));
    }
  }

  salvarNiveisLocal(atualizados);
  invalidarCacheTabela('configuracoes', targetCondo);
}

export async function excluirNivelAcesso(id: string, condominioId?: string): Promise<void> {
  const atuais = obterNiveisLocal();
  const atualizados = atuais.filter(n => n.id !== id);

  if (!condominioId || !isUUID(condominioId)) {
    throw new Error('Condomínio inválido para excluir nível de acesso no servidor.');
  }

  if (typeof navigator !== 'undefined' && navigator.onLine === false) {
    throw new Error('Exclusão de níveis de acesso exige conexão ativa com o servidor.');
  }

  const customizadosDoCondo = atualizados.filter(n => n.condominio_id === condominioId || !n.padrao_sistema);
  const { error } = await supabase
    .from('configuracoes')
    .update({ niveis_acesso: customizadosDoCondo } as any)
    .eq('condominio_id', condominioId);

  if (error) {
    throw new Error(formatarErroDetalhadoSupabase(error, 'Falha ao excluir nível de acesso no Supabase'));
  }

  salvarNiveisLocal(atualizados);
  invalidarCacheTabela('configuracoes', condominioId);
}

/**
 * Valida se um perfil de nível de acesso está sendo usado por algum operador.
 * Retorna a lista de nomes de operadores usando este perfil.
 */
export function verificarOperadoresEmUso(nivelId: string, operadores: any[]): string[] {
  if (!operadores || operadores.length === 0) return [];

  // Mapear correspondência com o nível ID (ex: 'nivel_0' -> nivel_acesso === 0, ou custom id)
  const nivelNum = nivelId.startsWith('nivel_') ? parseInt(nivelId.replace('nivel_', ''), 10) : NaN;

  const operadoresVinculados = operadores.filter(op => {
    if (op.nivel_acesso_custom_id === nivelId) return true;
    if (op.perfil_id === nivelId) return true;
    if (!isNaN(nivelNum) && op.nivel_acesso === nivelNum) return true;
    if (op.perfil === nivelId) return true;
    return false;
  });

  return operadoresVinculados.map(op => op.nome || op.login || 'Operador sem nome');
}

/**
 * Retorna o nome amigável de um perfil pelo seu ID ou nível numérico
 */
export function obterNomeNivel(nivelIdentificador: string | number | undefined, niveis?: NivelAcessoItem[]): string {
  if (nivelIdentificador === undefined || nivelIdentificador === null) return 'Nível Desconhecido';

  const lista = niveis || obterNiveisLocal();
  const idStr = String(nivelIdentificador);

  // Busca direta por ID
  const direto = lista.find(n => n.id === idStr);
  if (direto) return direto.nome;

  // Busca por 'nivel_' + id
  const porPrefixo = lista.find(n => n.id === `nivel_${idStr}`);
  if (porPrefixo) return porPrefixo.nome;

  // Fallbacks conhecidos
  switch (idStr) {
    case '0':
    case 'admin_geral':
      return 'Nível 0 — Administrador Geral';
    case '1':
    case 'admin':
    case 'admin_condominio':
    case 'admin_local':
    case 'master':
      return 'Nível 1 — Administrador de Condomínio';
    case '2':
    case 'supervisor':
      return 'Nível 2 — Supervisor de Segurança';
    case '3':
    case 'operador':
      return 'Nível 3 — Operador de Guarita';
    case '4':
    case 'sindico':
      return 'Nível 4 — Síndico (Visualização)';
    default:
      return idStr;
  }
}

/**
 * Clona as permissões de um perfil base para um novo perfil customizado
 */
export function clonarPermissoes(permissoesOrigem: PermissoesModulo): PermissoesModulo {
  return JSON.parse(JSON.stringify(permissoesOrigem || {}));
}

function ehIdNivelCustomizado(nivelId: string): boolean {
  const clean = String(nivelId || '').trim();
  return Boolean(clean && !['nivel_0', 'nivel_1', 'nivel_2', 'nivel_3', 'nivel_4'].includes(clean));
}

function normalizarIdNivel(nivel: string): string {
  const raw = String(nivel || '').trim();
  if (!raw) return 'nivel_3';
  if (raw.startsWith('nivel_') || raw.startsWith('custom_')) return raw;
  if (/^\d+$/.test(raw)) return `nivel_${raw}`;
  const todos = obterNiveisLocal();
  if (todos.some(n => n.id === raw)) return raw;
  return `nivel_${raw}`;
}

/**
 * Obtém permissões configuradas para um nível específico ('nivel_0'..'nivel_4' ou 'custom_*').
 * Nível personalizado inexistente falha fechado ({}).
 */
export function obterPermissoesPadraoNivel(nivel: string, niveis?: NivelAcessoItem[]): PermissoesModulo {
  const todos = niveis || obterNiveisLocal();
  const chave = normalizarIdNivel(nivel);
  const nivelDireto = todos.find(n => n.id === nivel || n.id === chave);
  if (nivelDireto) {
    return JSON.parse(JSON.stringify(nivelDireto.permissoes || {}));
  }
  if (ehIdNivelCustomizado(chave) || String(nivel || '').startsWith('custom_')) {
    return {};
  }
  const padrao = NIVEIS_PADRAO.find(n => n.id === chave) || NIVEIS_PADRAO.find(n => n.id === 'nivel_3');
  return JSON.parse(JSON.stringify(padrao?.permissoes || NIVEIS_PADRAO[3].permissoes));
}

function mesclarPermissoesBaseEOverrides(
  base: PermissoesModulo,
  overrides: Record<string, any> | null | undefined
): PermissoesModulo {
  const resultado: any = JSON.parse(JSON.stringify(base || {}));
  if (!overrides || typeof overrides !== 'object') return resultado;

  for (const [k, v] of Object.entries(overrides)) {
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      resultado[k] = {
        ...(resultado[k] && typeof resultado[k] === 'object' ? resultado[k] : {}),
        ...v
      };
    } else if (v !== undefined) {
      resultado[k] = v;
    }
  }
  return resultado;
}

/**
 * Extrai somente os overrides em relação ao nível base em configuracoes.niveis_acesso
 * para evitar congelar matrizes inteiras em operadores.permissoes.
 */
export function extrairOverridesOperador(
  permissoesAtuais: PermissoesModulo,
  nivelId: string,
  niveis?: NivelAcessoItem[],
  unidade?: string
): Record<string, any> {
  const base = obterPermissoesPadraoNivel(nivelId, niveis) as Record<string, any>;
  const atuais = (permissoesAtuais || {}) as Record<string, any>;
  const overrides: Record<string, any> = {};

  for (const [modKey, modVal] of Object.entries(atuais)) {
    if (modKey === 'unidade_acesso' || modKey === 'unidade') continue;
    if (!modVal || typeof modVal !== 'object' || Array.isArray(modVal)) continue;

    const baseMod = base[modKey] && typeof base[modKey] === 'object' ? base[modKey] : {};
    const diffMod: Record<string, any> = {};

    for (const [acaoKey, acaoVal] of Object.entries(modVal)) {
      if (acaoVal === undefined) continue;
      if (baseMod[acaoKey] === undefined || Boolean(acaoVal) !== Boolean(baseMod[acaoKey])) {
        diffMod[acaoKey] = Boolean(acaoVal);
      }
    }

    if (Object.keys(diffMod).length > 0) {
      overrides[modKey] = diffMod;
    }
  }

  const unidadeFinal = unidade || atuais.unidade_acesso || atuais.unidade;
  if (unidadeFinal) {
    overrides.unidade_acesso = unidadeFinal;
    overrides.unidade = unidadeFinal;
  }

  return overrides;
}

/**
 * Resolve as permissões efetivas de um operador:
 * combina configuracoes.niveis_acesso (fonte única) + overrides granulares de operadores.permissoes.
 * Sem fallback para localStorage legado de operadores.
 */
export function obterPermissoesOperador(operador: any): PermissoesModulo {
  if (!operador) return {};

  const idNivel = extrairIdNivel(operador);
  const todos = obterNiveisLocal();
  const nivelEncontrado = todos.find(n => n.id === idNivel);
  const ehCustom = ehIdNivelCustomizado(idNivel) && Boolean(operador.nivel_acesso_custom_id);

  // Nível personalizado inexistente falha fechado ({})
  if (ehCustom && !nivelEncontrado) {
    return {};
  }

  const base = obterPermissoesPadraoNivel(idNivel, todos);
  if (operador.permissoes && typeof operador.permissoes === 'object' && Object.keys(operador.permissoes).length > 0) {
    return mesclarPermissoesBaseEOverrides(base, operador.permissoes);
  }

  return base;
}

/**
 * Salva as permissões granulares diretamente no card do operador (somente no Supabase; fail-closed)
 */
export async function salvarPermissoesOperador(
  operadorId: string,
  permissoes: PermissoesModulo,
  loginOperador?: string,
  condominioId?: string
): Promise<boolean> {
  if (!operadorId && !loginOperador) {
    throw new Error('Operador não identificado para atualização de permissões.');
  }

  if (typeof navigator !== 'undefined' && navigator.onLine === false) {
    throw new Error('Alteração de permissões exige conexão ativa com o servidor Supabase.');
  }

  // Persiste primeiro no servidor Supabase (fail-closed: nunca simula sucesso local em caso de rejeição RLS/trigger)
  let query = supabase
    .from('operadores')
    .update({ permissoes } as any);

  if (operadorId && isUUID(operadorId)) {
    query = query.eq('id', operadorId);
  } else if (loginOperador) {
    query = query.eq('login', loginOperador.toLowerCase());
  } else {
    query = query.eq('login', operadorId.toLowerCase());
  }

  const updateRes = await query.select('id, condominio_id');

  if (updateRes.error) {
    throw new Error(formatarErroDetalhadoSupabase(updateRes.error, 'Falha ao persistir permissões do operador no Supabase'));
  }

  if (!Array.isArray(updateRes.data) || updateRes.data.length === 0) {
    throw new Error('Nenhum operador autorizado foi atualizado no servidor (ação bloqueada por RLS ou operador não encontrado).');
  }

  const atualizadoRow = updateRes.data[0];

  invalidarCacheTabela('operadores', condominioId || atualizadoRow?.condominio_id);

  if (typeof window !== 'undefined') {
    window.dispatchEvent(new CustomEvent('permissoes_operador_atualizadas', {
      detail: { operadorId, login: loginOperador, permissoes }
    }));
  }

  return true;
}

/**
 * Conta quantos módulos estão com acesso visual ativado
 */
export function contarModulosHabilitados(permissoes: PermissoesModulo): number {
  if (!permissoes) return 0;
  return Object.values(permissoes).filter((m: any) => m && m.visualizar === true).length;
}

export function extrairIdNivel(operador: any): string {
  if (!operador) return 'nivel_3';
  const ehAdminGeral = temAcessoGlobalExplicito(operador);
  if (ehAdminGeral) {
    const customAdm = String(operador.nivel_acesso_custom_id || '').trim();
    return customAdm || 'nivel_0';
  }

  const perfilPadrao = normalizarPerfilOperador(operador);
  const rawPerfil = String(operador.perfil || '').trim().toLowerCase();
  const ehSindicoPerfil = perfilPadrao === 'operador' && rawPerfil.includes('sind');
  const perfilNivelId =
    perfilPadrao === 'admin_condominio'
      ? 'nivel_1'
      : perfilPadrao === 'supervisor'
        ? 'nivel_2'
        : ehSindicoPerfil
          ? 'nivel_4'
          : 'nivel_3';

  if (operador.nivel_acesso_custom_id) {
    const customId = String(operador.nivel_acesso_custom_id).trim();
    const customLower = customId.toLowerCase();
    if (['0', '1', 'nivel_0', 'nivel_1'].includes(customLower)) {
      return perfilNivelId;
    }
    if (['2', 'nivel_2'].includes(customLower) && perfilPadrao !== 'admin_condominio' && perfilPadrao !== 'supervisor') {
      return perfilNivelId;
    }
    if (['4', 'nivel_4'].includes(customLower) && perfilPadrao !== 'admin_condominio' && perfilPadrao !== 'supervisor' && !ehSindicoPerfil) {
      return perfilNivelId;
    }
    if (['nivel_2', 'nivel_3', 'nivel_4'].includes(customLower)) {
      return customLower;
    }
    return customId;
  }

  return perfilNivelId;
}

export function resolverAcaoEmPermissoesModulo(permissoesModulo: any, modKey: string, acao: string): boolean | undefined {
  if (!permissoesModulo || typeof permissoesModulo !== 'object') return undefined;

  // 1. Verificação direta da chave exata
  if (permissoesModulo[acao] !== undefined) {
    return Boolean(permissoesModulo[acao]);
  }

  // 2. Aliases cruzados específicos por módulo (falha fechada, sem conceder acesso implícito)
  if (modKey === 'chaves') {
    if (acao === 'excluir') return permissoesModulo.excluir;
    if (acao === 'cadastrar' || acao === 'criar') return permissoesModulo.cadastrar ?? permissoesModulo.criar;
    if (acao === 'editar') return permissoesModulo.editar ?? permissoesModulo.cadastrar;
    if (acao === 'emprestar') return permissoesModulo.emprestar ?? permissoesModulo.criar;
    if (acao === 'devolver') return permissoesModulo.devolver ?? permissoesModulo.editar;
  }

  if (modKey === 'encomendas') {
    if (acao === 'cadastrar_entregador') return permissoesModulo.cadastrar_entregador ?? permissoesModulo.criar;
    if (acao === 'entrada_lote' || acao === 'criar_lote') return permissoesModulo.entrada_lote ?? permissoesModulo.criar_lote ?? permissoesModulo.criar;
    if (acao === 'triagem') return permissoesModulo.triagem ?? permissoesModulo.criar;
    if (acao === 'baixa') return permissoesModulo.baixa ?? permissoesModulo.criar;
    if (acao === 'editar_pacote' || acao === 'editar_lotes') return permissoesModulo.editar_pacote ?? permissoesModulo.editar_lotes ?? permissoesModulo.editar;
    if (acao === 'excluir_pacote' || acao === 'excluir_lotes') return permissoesModulo.excluir_pacote ?? permissoesModulo.excluir_lotes ?? permissoesModulo.excluir;
    if (acao === 'dossie' || acao === 'historico') return permissoesModulo.dossie ?? permissoesModulo.historico ?? permissoesModulo.visualizar;
  }

  if (modKey === 'autorizados' || modKey === 'prestadores') {
    if (acao === 'cadastrar' || acao === 'criar') return permissoesModulo.cadastrar ?? permissoesModulo.criar;
    if (acao === 'dar_entrada') return permissoesModulo.dar_entrada ?? permissoesModulo.cadastrar ?? permissoesModulo.criar;
    if (acao === 'dar_saida') return permissoesModulo.dar_saida ?? permissoesModulo.editar;
    if (acao === 'editar') return permissoesModulo.editar ?? permissoesModulo.cadastrar;
    if (acao === 'excluir') return permissoesModulo.excluir;
  }

  if (modKey === 'custodia') {
    if (acao === 'receber' || acao === 'criar') return permissoesModulo.receber ?? permissoesModulo.criar;
    if (acao === 'baixa') return permissoesModulo.baixa ?? permissoesModulo.editar;
    if (acao === 'auditoria') return permissoesModulo.auditoria ?? permissoesModulo.visualizar;
  }

  if (modKey === 'manutencao') {
    if (acao === 'abrir_os' || acao === 'criar') return permissoesModulo.abrir_os ?? permissoesModulo.criar;
    if (acao === 'concluir' || acao === 'editar') return permissoesModulo.concluir ?? permissoesModulo.editar;
  }

  if (modKey === 'rondas') {
    if (acao === 'iniciar_ronda') return permissoesModulo.iniciar_ronda ?? permissoesModulo.criar;
    if (acao === 'cadastrar_pontos' || acao === 'criar') return permissoesModulo.cadastrar_pontos ?? permissoesModulo.criar;
    if (acao === 'setores') return permissoesModulo.setores ?? permissoesModulo.editar;
  }

  if (modKey === 'passagem_posto' || modKey === 'passagem') {
    if (acao === 'assumir_posto' || acao === 'criar') return permissoesModulo.assumir_posto ?? permissoesModulo.criar;
    if (acao === 'relatorio') return permissoesModulo.relatorio ?? permissoesModulo.visualizar;
  }

  if (modKey === 'cadastros') {
    if (acao === 'operadores' || acao === 'cadastrar_operadores') return permissoesModulo.operadores ?? permissoesModulo.cadastrar_operadores ?? permissoesModulo.criar;
    if (acao === 'visualizar_operadores') return permissoesModulo.visualizar_operadores ?? permissoesModulo.operadores ?? permissoesModulo.visualizar;
    if (acao === 'editar_operadores') return permissoesModulo.editar_operadores ?? permissoesModulo.operadores ?? permissoesModulo.editar;
    if (acao === 'alterar_senha_operador') return permissoesModulo.alterar_senha_operador ?? permissoesModulo.editar_operadores ?? permissoesModulo.operadores;
    if (acao === 'excluir_operadores') return permissoesModulo.excluir_operadores ?? permissoesModulo.excluir ?? false;
    if (acao === 'moradores' || acao === 'gerenciar_moradores') return permissoesModulo.moradores ?? permissoesModulo.criar;
    if (acao === 'visualizar_moradores') return permissoesModulo.visualizar_moradores ?? permissoesModulo.moradores ?? permissoesModulo.visualizar;
    if (acao === 'cadastrar_morador') return permissoesModulo.cadastrar_morador ?? permissoesModulo.moradores ?? permissoesModulo.criar;
    if (acao === 'editar_morador') return permissoesModulo.editar_morador ?? permissoesModulo.moradores ?? permissoesModulo.editar;
    if (acao === 'excluir_morador') return permissoesModulo.excluir_morador ?? permissoesModulo.excluir ?? false;
    if (acao === 'gerenciar_veiculos' || acao === 'veiculos') return permissoesModulo.gerenciar_veiculos ?? permissoesModulo.moradores ?? permissoesModulo.editar;
    if (acao === 'vincular_tags' || acao === 'tags_rfid') return permissoesModulo.vincular_tags ?? permissoesModulo.moradores ?? permissoesModulo.editar;
    if (acao === 'status_acesso_morador') return permissoesModulo.status_acesso_morador ?? permissoesModulo.editar_morador ?? permissoesModulo.moradores;
    if (acao === 'exportar_moradores') return permissoesModulo.exportar_moradores ?? permissoesModulo.visualizar_moradores ?? permissoesModulo.visualizar;
    if (acao === 'configurar_condominio') return permissoesModulo.configurar_condominio ?? permissoesModulo.condominios ?? permissoesModulo.editar;
    if (acao === 'condominios') return permissoesModulo.condominios ?? permissoesModulo.criar;
    if (acao === 'gerenciar_niveis') return permissoesModulo.gerenciar_niveis ?? permissoesModulo.editar;
    if (acao === 'excluir') return permissoesModulo.excluir ?? false;
  }

  if (modKey === 'moradores') {
    if (acao === 'adicionar' || acao === 'cadastrar' || acao === 'criar') return permissoesModulo.adicionar ?? permissoesModulo.criar ?? permissoesModulo.cadastrar;
    if (acao === 'editar') return permissoesModulo.editar;
    if (acao === 'excluir') return permissoesModulo.excluir;
  }

  if (modKey === 'ocorrencias') {
    if (acao === 'criar' || acao === 'cadastrar') return permissoesModulo.criar ?? permissoesModulo.cadastrar;
    if (acao === 'resolver' || acao === 'editar') return permissoesModulo.resolver ?? permissoesModulo.editar;
  }

  if (modKey === 'bancada') {
    if (acao === 'lancar' || acao === 'criar') return permissoesModulo.lancar ?? permissoesModulo.criar;
    if (acao === 'baixa' || acao === 'editar') return permissoesModulo.baixa ?? permissoesModulo.editar;
    if (acao === 'zerar' || acao === 'excluir') return permissoesModulo.zerar ?? permissoesModulo.excluir;
    if (acao === 'historico') return permissoesModulo.historico ?? permissoesModulo.visualizar;
  }

  if (modKey === 'historico_absoluto') {
    if (acao === 'ver_feed' || acao === 'ver_metricas' || acao === 'exportar_csv') return permissoesModulo[acao] ?? permissoesModulo.visualizar;
    if (acao === 'limpar_dados' || acao === 'excluir') return permissoesModulo.limpar_dados ?? permissoesModulo.excluir;
  }

  if (modKey === 'materiais') {
    if (acao === 'cadastrar_equipamentos' || acao === 'criar' || acao === 'cadastrar') return permissoesModulo.cadastrar_equipamentos ?? permissoesModulo.criar;
    if (acao === 'alterar_status') return permissoesModulo.alterar_status ?? permissoesModulo.editar;
    if (acao === 'editar') return permissoesModulo.editar;
    if (acao === 'excluir') return permissoesModulo.excluir;
  }

  if (modKey === 'reservas') {
    if (acao === 'criar' || acao === 'solicitar') return permissoesModulo.criar;
    if (acao === 'aprovar' || acao === 'recusar') return permissoesModulo.aprovar ?? permissoesModulo.editar;
    if (acao === 'cancelar') return permissoesModulo.cancelar ?? permissoesModulo.excluir;
    if (acao === 'gerenciar_areas') return permissoesModulo.gerenciar_areas ?? permissoesModulo.editar;
    if (acao === 'vistoria') return permissoesModulo.vistoria ?? permissoesModulo.editar;
  }

  if (modKey === 'controle_acesso') {
    if (acao === 'liberar_entrada' || acao === 'entrada' || acao === 'criar') return permissoesModulo.liberar_entrada ?? permissoesModulo.criar;
    if (acao === 'registrar_saida' || acao === 'saida') return permissoesModulo.registrar_saida ?? permissoesModulo.editar;
    if (acao === 'bloquear' || acao === 'blacklist') return permissoesModulo.bloquear ?? permissoesModulo.editar;
    if (acao === 'gerar_passe_qr' || acao === 'passe_qr') return permissoesModulo.gerar_passe_qr ?? permissoesModulo.criar;
    if (acao === 'configurar_portoes' || acao === 'portoes') return permissoesModulo.configurar_portoes ?? permissoesModulo.editar;
  }

  if (modKey === 'configuracoes') {
    if (acao === 'gerenciar_niveis') return permissoesModulo.gerenciar_niveis ?? permissoesModulo.editar;
    if (acao === 'feature_flags') return permissoesModulo.feature_flags ?? permissoesModulo.editar;
  }

  // 3. Fallback genérico: se for ação de criação e tiver 'criar', ou edição e tiver 'editar'
  if (acao === 'criar' && permissoesModulo.criar !== undefined) return Boolean(permissoesModulo.criar);
  if (acao === 'editar' && permissoesModulo.editar !== undefined) return Boolean(permissoesModulo.editar);
  if (acao === 'excluir' && permissoesModulo.excluir !== undefined) return Boolean(permissoesModulo.excluir);

  return undefined;
}

/**
 * Verifica se um operador logado possui uma permissão específica.
 * Fonte única sincronizada com public.operador_tem_permissao_modulo() e temPermissaoModuloBackend().
 */
export function verificarPermissao(
  operador: any,
  modulo: keyof PermissoesModulo | string,
  acao: string
): boolean {
  if (!operador || operador.ativo === false) return false;

  const perfilStr = String(operador.perfil || '').trim().toLowerCase();
  const idNivel = extrairIdNivel(operador);
  const ehAdminGeral = temAcessoGlobalExplicito(operador);
  const ehNivelCustom = !ehAdminGeral && Boolean(operador.nivel_acesso_custom_id) && ehIdNivelCustomizado(idNivel);
  const perfilPadrao = normalizarPerfilOperador(operador);
  const ehAdminCondominioLocal = !ehAdminGeral && perfilPadrao === 'admin_condominio' && perfilStr === 'admin_condominio';
  const ehSupervisor = !ehAdminGeral && !ehAdminCondominioLocal && perfilPadrao === 'supervisor';

  // REGRA ESTRITA DE SEGURANÇA: Operador/Porteiro NUNCA pode excluir materiais do posto (independente de nivel_acesso=0/1 legado)
  if (modulo === 'materiais' && (acao === 'excluir' || acao === 'excluir_equipamento')) {
    if (!ehAdminGeral && !ehAdminCondominioLocal && !ehSupervisor && !ehNivelCustom && (perfilStr === 'operador' || perfilStr === 'porteiro' || perfilStr === '')) {
      return false;
    }
  }

  // Normalização de sinônimos de módulos
  let modKey = String(modulo).toLowerCase();
  if (modKey === 'prestadores') modKey = 'autorizados';
  if (modKey === 'passagem') modKey = 'passagem_posto';

  // REGRA ESTRITA DE SEGURANÇA: Módulo de Configurações é EXCLUSIVO para Administrador Geral com acesso_global_condominios = true
  if (modKey === 'configuracoes') {
    return ehAdminGeral;
  }

  // REGRA ESTRITA DE SEGURANÇA: Operações administrativas globais e gestão administrativa seguem estritamente o perfil oficial
  if (modKey === 'cadastros') {
    if (acao === 'condominios' || acao === 'gerenciar_niveis') {
      return ehAdminGeral;
    }
    if (
      acao === 'operadores' ||
      acao === 'cadastrar_operadores' ||
      acao === 'editar_operadores' ||
      acao === 'alterar_senha_operador' ||
      acao === 'excluir_operadores' ||
      acao === 'configurar_condominio'
    ) {
      if (!ehAdminGeral && !ehAdminCondominioLocal) {
        return false;
      }
    }
  }

  if (modKey === 'historico_absoluto' && (acao === 'limpar_dados' || acao === 'excluir')) {
    if (!ehAdminGeral && !ehAdminCondominioLocal) {
      return false;
    }
  }

  // Fail-closed imediato para Administrador Geral
  if (ehAdminGeral) {
    return true;
  }

  const todos = obterNiveisLocal();
  let nivelObj = todos.find(n => n.id === idNivel);

  // Nível personalizado inexistente em configuracoes.niveis_acesso falha fechado (nunca herda overrides nem NIVEIS_PADRAO)
  if (ehNivelCustom && (!nivelObj || !nivelObj.permissoes || typeof nivelObj.permissoes !== 'object')) {
    return false;
  }

  // REGRA ESTRITA RBAC: Perfil de Síndico (Nível 4)
  const ehSindico = !ehAdminCondominioLocal && !ehSupervisor && (perfilStr.includes('sind') || Boolean(operador.eSindico));
  if (ehSindico) {
    const permDiretas = obterPermissoesOperador(operador);
    const modCfg: any = permDiretas ? ((permDiretas as any)[modKey] || (permDiretas as any)[modulo]) : null;

    if (modCfg && modCfg.visualizar === false) {
      return false;
    }

    if (modKey === 'ocorrencias') {
      return acao === 'visualizar' || acao === 'criar' || acao === 'resolver';
    }

    if (acao === 'visualizar' || acao === 'relatorio' || acao === 'dossie' || acao === 'historico' || acao === 'ver_feed' || acao === 'ver_metricas' || acao === 'exportar_csv' || acao === 'visualizar_moradores' || acao === 'visualizar_operadores' || acao === 'auditoria') {
      if (modCfg && modCfg.visualizar !== undefined) {
        return Boolean(modCfg.visualizar);
      }
      return true;
    }

    return false;
  }

  // 1. VERIFICAÇÃO PRIORITÁRIA: Overrides explícitos salvos em operadores.permissoes
  const permissoesDiretas = (operador.permissoes && typeof operador.permissoes === 'object') ? operador.permissoes : null;
  if (permissoesDiretas) {
    const modConfig: any =
      (permissoesDiretas as any)[modKey] ||
      (permissoesDiretas as any)[modulo] ||
      (modKey === 'autorizados' ? (permissoesDiretas as any).prestadores : undefined) ||
      (modKey === 'passagem_posto' ? (permissoesDiretas as any).passagem : undefined);

    if (modConfig && typeof modConfig === 'object') {
      if (modConfig.visualizar === false) {
        if (!(modKey === 'cadastros' && ['visualizar_moradores', 'cadastrar_morador', 'gerenciar_veiculos'].includes(acao))) {
          return false;
        }
      }
      if (acao === 'visualizar' && modConfig.visualizar !== undefined) {
        return Boolean(modConfig.visualizar);
      }
      const resAcaoDireta = resolverAcaoEmPermissoesModulo(modConfig, modKey, acao);
      if (resAcaoDireta !== undefined) {
        return Boolean(resAcaoDireta);
      }
    }
  }

  // 2. VERIFICAÇÃO POR PERFIL / NÍVEL DE ACESSO EM configuracoes.niveis_acesso
  if (!nivelObj && !ehNivelCustom) {
    if (ehAdminCondominioLocal) nivelObj = todos.find(n => n.id === 'nivel_1') || NIVEIS_PADRAO[1];
    else if (perfilPadrao === 'supervisor') nivelObj = todos.find(n => n.id === 'nivel_2') || NIVEIS_PADRAO[2];
    else nivelObj = todos.find(n => n.id === 'nivel_3') || NIVEIS_PADRAO[3];
  }

  if (nivelObj && nivelObj.permissoes) {
    const permissoesModulo: any =
      (nivelObj.permissoes as any)[modKey] ||
      (nivelObj.permissoes as any)[modulo] ||
      (modKey === 'autorizados' ? (nivelObj.permissoes as any).prestadores : undefined) ||
      (modKey === 'passagem_posto' ? (nivelObj.permissoes as any).passagem : undefined);

    if (permissoesModulo && typeof permissoesModulo === 'object') {
      if (permissoesModulo.visualizar === false) {
        if (!(modKey === 'cadastros' && ['visualizar_moradores', 'cadastrar_morador', 'gerenciar_veiculos'].includes(acao))) {
          return false;
        }
      }
      if (acao === 'visualizar' && permissoesModulo.visualizar !== undefined) {
        return Boolean(permissoesModulo.visualizar);
      }
      const resAcaoNivel = resolverAcaoEmPermissoesModulo(permissoesModulo, modKey, acao);
      if (resAcaoNivel !== undefined) {
        return Boolean(resAcaoNivel);
      }
    }
  }

  return false;
}
