import React, { useState } from 'react';
import { supabase } from '../services/supabase';
import { 
  User, 
  Lock, 
  Key, 
  ShieldCheck, 
  Building2, 
  Save, 
  X, 
  CheckCircle2, 
  AlertCircle,
  Eye,
  EyeOff,
  Camera,
  Trash2,
  Briefcase
} from 'lucide-react';
import {
  uploadFotoComprimidaStorage,
  normalizarCaminhoStorageParaBanco
} from '../services/imageUtils';
import { ImagemOtimizada } from './ImagemOtimizada';
import {
  normalizarPerfilOperador,
  temAcessoGlobalExplicito,
  ehAdminCondominio
} from '../services/autorizacaoService';
import { isUUID } from '../services/condominioService';

interface ModalMeuPerfilProps {
  isOpen: boolean;
  onClose: () => void;
  operador: any;
  condominio: any;
  onOperadorAtualizado?: (operadorAtualizado: any) => void;
}

export default function ModalMeuPerfil({
  isOpen,
  onClose,
  operador,
  condominio,
  onOperadorAtualizado
}: ModalMeuPerfilProps) {
  const [nome, setNome] = useState(operador?.nome || '');
  const [fotoUrl, setFotoUrl] = useState(operador?.foto_url || '');
  const [senhaAtual, setSenhaAtual] = useState('');
  const [novaSenha, setNovaSenha] = useState('');
  const [confirmaNovaSenha, setConfirmaNovaSenha] = useState('');
  const [mostrarSenhas, setMostrarSenhas] = useState(false);
  const [loading, setLoading] = useState(false);
  const [mensagem, setMensagem] = useState<{ tipo: 'sucesso' | 'erro'; texto: string } | null>(null);

  const [enviandoFoto, setEnviandoFoto] = useState(false);

  if (!isOpen || !operador) return null;

  const handleFotoUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setMensagem(null);

    if (typeof navigator !== 'undefined' && !navigator.onLine) {
      setMensagem({
        tipo: 'erro',
        texto: 'Conecte-se à internet para enviar a foto de perfil ao Storage privado.'
      });
      return;
    }

    setEnviandoFoto(true);
    try {
      const condIdUpload = String(condominio?.id || operador?.condominio_id || '').trim();
      const authRes = await supabase.auth.getUser().catch(() => ({ data: { user: null } } as any));
      const authUid = String(authRes?.data?.user?.id || operador?.auth_user_id || '').trim();

      // Estratégia segura para foto de perfil:
      // - Se o usuário possui auth.uid(), grava na pasta privada pessoal operadores/{auth_uid}/...
      //   (funciona mesmo para admin_geral sem condomínio ativo e não concede acesso a outros condomínios).
      // - Caso contrário, utiliza o condomínio ativo validado como UUID.
      if (isUUID(authUid)) {
        const res = await uploadFotoComprimidaStorage({
          file,
          pasta: 'operadores',
          escopoUsuarioAuthId: authUid,
          maxWidth: 400,
          maxHeight: 400,
          qualidade: 0.82
        });
        setFotoUrl(normalizarCaminhoStorageParaBanco(res.storagePath));
      } else if (isUUID(condIdUpload)) {
        const res = await uploadFotoComprimidaStorage({
          file,
          pasta: 'operadores',
          condominioId: condIdUpload,
          maxWidth: 400,
          maxHeight: 400,
          qualidade: 0.82
        });
        setFotoUrl(normalizarCaminhoStorageParaBanco(res.storagePath));
      } else {
        throw new Error('Identidade Supabase Auth ou condomínio ativo necessário para armazenar a foto com segurança.');
      }
    } catch (err: any) {
      console.error('Erro ao enviar foto de perfil ao Storage privado:', err);
      setMensagem({
        tipo: 'erro',
        texto: `Não foi possível enviar a foto para o Storage privado: ${err?.message || 'verifique as políticas do bucket.'}`
      });
    } finally {
      setEnviandoFoto(false);
    }
  };

  const getNivelNome = () => {
    if (temAcessoGlobalExplicito(operador) || normalizarPerfilOperador(operador) === 'admin_geral') {
      return 'Administrador Geral (Global)';
    }
    if (ehAdminCondominio(operador)) {
      return 'Administrador de Condomínio';
    }
    if (normalizarPerfilOperador(operador) === 'supervisor') {
      return 'Supervisor Operacional';
    }
    if (operador?.nivel_acesso === 4 || String(operador?.funcao || '').toLowerCase().includes('síndico') || String(operador?.funcao || '').toLowerCase().includes('sindico')) {
      return 'Síndico (Somente Leitura)';
    }
    return 'Operador / Porteiro';
  };

  const handleSalvarPerfil = async (e: React.FormEvent) => {
    e.preventDefault();
    setMensagem(null);

    if (!nome.trim()) {
      setMensagem({ tipo: 'erro', texto: 'O nome do operador não pode ficar vazio.' });
      return;
    }

    if (novaSenha.trim()) {
      if (novaSenha.trim().length < 6) {
        setMensagem({ tipo: 'erro', texto: 'A nova senha deve ter no mínimo 6 caracteres (padrão Supabase Auth).' });
        return;
      }
      if (novaSenha !== confirmaNovaSenha) {
        setMensagem({ tipo: 'erro', texto: 'A confirmação de senha não confere com a nova senha digitada.' });
        return;
      }
    }

    setLoading(true);
    try {
      if (novaSenha.trim()) {
        const { error: authErr } = await supabase.auth.updateUser({
          password: novaSenha.trim()
        });
        if (authErr) throw authErr;
      }

      const fotoNormalizada = fotoUrl ? normalizarCaminhoStorageParaBanco(fotoUrl) : null;
      if (fotoNormalizada && fotoNormalizada.startsWith('data:')) {
        setMensagem({
          tipo: 'erro',
          texto: 'Selecione ou reenvie a foto para o Storage privado antes de salvar (base64 não é aceito no banco).'
        });
        setLoading(false);
        return;
      }

      const payload: { nome: string; foto_url?: string | null } = {
        nome: nome.trim(),
        foto_url: fotoNormalizada
      };

      const { error } = await supabase
        .from('operadores')
        .update(payload)
        .eq('id', operador.id);

      if (error) throw error;

      const operadorAtualizado = {
        ...operador,
        nome: payload.nome,
        foto_url: payload.foto_url
      };

      if (onOperadorAtualizado) {
        onOperadorAtualizado(operadorAtualizado);
      }

      setSenhaAtual('');
      setNovaSenha('');
      setConfirmaNovaSenha('');
      setMensagem({ 
        tipo: 'sucesso', 
        texto: novaSenha.trim() 
          ? 'Foto, dados e senha atualizados com segurança no Supabase Auth!' 
          : 'Foto de perfil e dados atualizados com sucesso!' 
      });
    } catch (err: any) {
      setMensagem({ tipo: 'erro', texto: `Falha ao atualizar dados: ${err.message || 'Erro desconhecido'}` });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div 
      className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-3 sm:p-4 overflow-y-auto"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="bg-white dark:bg-slate-900 rounded-3xl shadow-2xl w-full max-w-lg max-h-[90vh] sm:max-h-[88vh] flex flex-col border border-slate-200 dark:border-slate-800 animate-in fade-in zoom-in-95 duration-200 overflow-hidden my-auto">
        {/* Cabeçalho */}
        <div className="bg-slate-900 px-5 sm:px-6 py-4 flex items-center justify-between text-white shrink-0 border-b border-slate-800">
          <div className="flex items-center gap-2.5">
            <div className="w-9 h-9 rounded-xl bg-emerald-500/20 text-emerald-400 flex items-center justify-center font-bold">
              <User className="w-5 h-5" />
            </div>
            <div>
              <h3 className="font-bold text-base leading-tight">Meu Perfil & Segurança</h3>
              <p className="text-xs text-slate-400">Gerencie seus dados e altere sua senha de acesso</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition cursor-pointer"
            aria-label="Fechar"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Conteúdo com Scroll direcionado para nunca vazar da tela */}
        <div className="p-4 sm:p-6 space-y-4 sm:space-y-5 overflow-y-auto flex-1 overscroll-contain text-slate-800 dark:text-slate-100">
          {mensagem && (
            <div className={`p-3.5 rounded-xl text-xs font-semibold flex items-center gap-2.5 ${
              mensagem.tipo === 'sucesso' 
                ? 'bg-emerald-50 text-emerald-800 border border-emerald-200' 
                : 'bg-red-50 text-red-700 border border-red-200'
            }`}>
              {mensagem.tipo === 'sucesso' ? (
                <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
              ) : (
                <AlertCircle className="w-4 h-4 text-red-600 shrink-0" />
              )}
              <span>{mensagem.texto}</span>
            </div>
          )}

          {/* Foto de Perfil do Operador */}
          <div className="flex items-center gap-4 bg-slate-50 dark:bg-slate-800/60 p-3.5 rounded-2xl border border-slate-200 dark:border-slate-700/80">
            <div className="relative group shrink-0">
              {fotoUrl ? (
                <ImagemOtimizada
                  src={fotoUrl}
                  alt={nome}
                  permitirAmpliar={true}
                  className="w-16 h-16 rounded-2xl object-cover border-2 border-emerald-500 shadow-sm"
                />
              ) : (
                <div className="w-16 h-16 rounded-2xl bg-slate-800 text-emerald-400 font-black text-xl flex items-center justify-center border-2 border-slate-700 shadow-sm">
                  {nome ? nome.charAt(0).toUpperCase() : 'OP'}
                </div>
              )}
            </div>

            <div className="flex-1 space-y-1">
              <span className="text-xs font-bold text-slate-800 dark:text-slate-200 block">Foto de Perfil</span>
              <p className="text-[11px] text-slate-500 dark:text-slate-400">Aparecerá no cabeçalho e nos relatórios de portaria.</p>
              <div className="flex items-center gap-2 pt-0.5">
                <label className={`px-3 py-1.5 bg-slate-900 hover:bg-slate-800 text-white rounded-xl text-xs font-bold flex items-center gap-1.5 transition shadow-2xs ${enviandoFoto ? 'opacity-60 cursor-wait' : 'cursor-pointer'}`}>
                  <Camera className="w-3.5 h-3.5 text-emerald-400" />
                  <span>{enviandoFoto ? 'Enviando...' : (fotoUrl ? 'Trocar Foto' : 'Tirar / Carregar Foto')}</span>
                  <input
                    type="file"
                    accept="image/*"
                    capture="user"
                    disabled={enviandoFoto}
                    onChange={handleFotoUpload}
                    className="hidden"
                  />
                </label>
                {fotoUrl && (
                  <button
                    type="button"
                    onClick={() => setFotoUrl('')}
                    className="p-1.5 text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/40 rounded-xl transition cursor-pointer"
                    title="Remover foto"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                )}
              </div>
            </div>
          </div>

          {/* Cards de Identificação */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
            <div className="bg-slate-50 dark:bg-slate-800/60 p-3 rounded-xl border border-slate-200 dark:border-slate-700/80 space-y-1">
              <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 flex items-center gap-1">
                <Briefcase className="w-3 h-3 text-blue-600 dark:text-blue-400" /> Função no App
              </span>
              <p className="text-xs font-bold text-slate-800 dark:text-slate-100 truncate">
                {operador?.funcao || operador?.cargo || getNivelNome()}
              </p>
            </div>

            <div className="bg-slate-50 dark:bg-slate-800/60 p-3 rounded-xl border border-slate-200 dark:border-slate-700/80 space-y-1">
              <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 flex items-center gap-1">
                <ShieldCheck className="w-3 h-3 text-emerald-600 dark:text-emerald-400" /> Nível de Acesso
              </span>
              <p className="text-xs font-bold text-slate-800 dark:text-slate-100">
                {getNivelNome()}
              </p>
            </div>

            <div className="bg-slate-50 dark:bg-slate-800/60 p-3 rounded-xl border border-slate-200 dark:border-slate-700/80 space-y-1 sm:col-span-1">
              <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 flex items-center gap-1">
                <Building2 className="w-3 h-3 text-emerald-600 dark:text-emerald-400" /> Condomínio
              </span>
              <p className="text-xs font-bold text-slate-800 dark:text-slate-100 truncate" title={condominio?.nome || 'Não definido'}>
                {condominio?.nome || 'Administração Geral'}
              </p>
            </div>
          </div>

          <form onSubmit={handleSalvarPerfil} className="space-y-4">
            <div>
              <label className="block text-xs font-bold uppercase tracking-wider text-slate-700 dark:text-slate-300 mb-1">
                Nome de Exibição
              </label>
              <input
                type="text"
                required
                value={nome}
                onChange={(e) => setNome(e.target.value)}
                className="w-full p-2.5 bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-xl text-sm font-semibold text-slate-900 dark:text-white focus:bg-white dark:focus:bg-slate-700 focus:outline-none focus:ring-2 focus:ring-emerald-500"
              />
            </div>

            <div>
              <label className="block text-xs font-bold uppercase tracking-wider text-slate-700 dark:text-slate-300 mb-1">
                Usuário / Login (Fixo)
              </label>
              <input
                type="text"
                disabled
                value={operador.login}
                className="w-full p-2.5 bg-slate-100 dark:bg-slate-850 border border-slate-200 dark:border-slate-750 rounded-xl text-sm font-mono text-slate-500 dark:text-slate-400 cursor-not-allowed"
              />
              <span className="text-[10px] text-slate-400 dark:text-slate-500 mt-0.5 block">
                O login é único e só pode ser alterado pelo Administrador do sistema.
              </span>
            </div>

            {/* Seção Alterar Senha */}
            <div className="pt-3 border-t border-slate-200 dark:border-slate-800 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold uppercase tracking-wider text-slate-900 dark:text-slate-100 flex items-center gap-1.5">
                  <Key className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" /> Alterar Senha de Acesso
                </span>
                <button
                  type="button"
                  onClick={() => setMostrarSenhas(!mostrarSenhas)}
                  className="text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200 text-xs flex items-center gap-1 cursor-pointer"
                >
                  {mostrarSenhas ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                  <span>{mostrarSenhas ? 'Ocultar' : 'Visualizar'}</span>
                </button>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-[11px] font-bold text-slate-600 dark:text-slate-300 mb-1">
                    Nova Senha
                  </label>
                  <input
                    type={mostrarSenhas ? 'text' : 'password'}
                    value={novaSenha}
                    onChange={(e) => setNovaSenha(e.target.value)}
                    placeholder="Mínimo 4 dígitos"
                    className="w-full p-2.5 bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-xl text-xs font-semibold text-slate-900 dark:text-white focus:bg-white dark:focus:bg-slate-700 focus:outline-none focus:ring-2 focus:ring-emerald-500"
                  />
                </div>

                <div>
                  <label className="block text-[11px] font-bold text-slate-600 dark:text-slate-300 mb-1">
                    Confirmar Nova Senha
                  </label>
                  <input
                    type={mostrarSenhas ? 'text' : 'password'}
                    value={confirmaNovaSenha}
                    onChange={(e) => setConfirmaNovaSenha(e.target.value)}
                    placeholder="Repita a nova senha"
                    className="w-full p-2.5 bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-xl text-xs font-semibold text-slate-900 dark:text-white focus:bg-white dark:focus:bg-slate-700 focus:outline-none focus:ring-2 focus:ring-emerald-500"
                  />
                </div>
              </div>
              <p className="text-[10px] text-slate-400 dark:text-slate-500">
                Deixe os campos de senha em branco se desejar manter sua senha atual inalterada.
              </p>
            </div>

            {/* Botões de Ação Fixos no Rodapé do Formulário */}
            <div className="pt-3 border-t border-slate-200 dark:border-slate-800 flex items-center justify-end gap-2.5 shrink-0 bg-white dark:bg-slate-900 sticky bottom-0 -mx-4 -mb-4 sm:-mx-6 sm:-mb-6 px-4 py-3 sm:px-6 sm:py-3.5 z-10 shadow-xs">
              <button
                type="button"
                onClick={onClose}
                className="px-4 py-2 text-xs font-bold text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-xl transition cursor-pointer"
              >
                Fechar
              </button>
              <button
                type="submit"
                disabled={loading}
                className="bg-emerald-600 hover:bg-emerald-500 active:scale-95 text-white font-bold px-5 py-2.5 rounded-xl text-xs flex items-center gap-1.5 transition shadow-sm disabled:opacity-50 cursor-pointer"
              >
                <Save className="w-3.5 h-3.5" />
                {loading ? 'Salvando...' : 'Salvar Alterações'}
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
}
