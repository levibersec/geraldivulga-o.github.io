/**
 * GERAL DIVULGAÇÃO — APP.JS v2.0
 * ================================
 * Organizado em módulos:
 *   1. CONFIG
 *   2. STORAGE (dados locais)
 *   3. SEGURANÇA
 *   4. AUTH / DISCORD OAUTH2
 *   5. NAVEGAÇÃO
 *   6. UI — NAVBAR
 *   7. UI — HOME
 *   8. UI — CARDS
 *   9. UI — LISTA
 *  10. UI — DETALHE
 *  11. UI — FORMULÁRIO
 *  12. UI — PERFIL
 *  13. UI — ADMIN
 *  14. TOAST / FEEDBACK
 *  15. INIT
 *
 * CLIENT ID DISCORD: 1493256628596899970
 * Redirecionar: OAuth2 → Redirects → http://127.0.0.1:5500/index.html
 */

'use strict';

/* ============================================================
   1. CONFIG
   ============================================================ */
const CONFIG = Object.freeze({
  DISCORD_CLIENT_ID: '1493256628596899970',
  DISCORD_API: 'https://discord.com/api/v10',
  STORAGE_KEY: {
    SERVERS:      'gd_servers',
    USERS:        'gd_users',
    CURRENT_USER: 'gd_currentUser',
    VOTES:        'gd_votes',
    STATE:        'gd_discord_state'
  },
  PLACEHOLDER: {
    BANNER: 'https://via.placeholder.com/1200x350/5865F2/ffffff?text=Servidor+Discord',
    ICON:   'https://via.placeholder.com/150/5865F2/ffffff?text=GD'
  }
});

/* ============================================================
   2. STORAGE
   ============================================================ */
const Storage = {
  get(key, fallback = null) {
    try {
      const raw = localStorage.getItem(key);
      return raw !== null ? JSON.parse(raw) : fallback;
    } catch { return fallback; }
  },
  set(key, value) {
    try { localStorage.setItem(key, JSON.stringify(value)); return true; }
    catch { return false; }
  },
  remove(key) { localStorage.removeItem(key); }
};

/* ============================================================
   3. SEGURANÇA
   ============================================================ */
const Security = {
  /**
   * Escapa HTML para prevenir XSS
   */
  escapeHtml(str) {
    if (typeof str !== 'string') return '';
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;');
  },

  /**
   * Valida se uma URL é segura (https:// ou http://)
   */
  isValidUrl(url) {
    if (!url || typeof url !== 'string') return false;
    try {
      const u = new URL(url.trim());
      return u.protocol === 'https:' || u.protocol === 'http:';
    } catch { return false; }
  },

  /**
   * Valida se é um link válido do Discord
   */
  isValidDiscordInvite(url) {
    if (!this.isValidUrl(url)) return false;
    return /^https?:\/\/(discord\.gg|discord\.com\/invite)\/.+/.test(url.trim());
  },

  /**
   * Sanitiza texto removendo HTML e limitando tamanho
   */
  sanitizeText(str, maxLen = 500) {
    if (typeof str !== 'string') return '';
    return str.trim().replace(/<[^>]*>/g, '').slice(0, maxLen);
  },

  /**
   * Gera um state CSRF aleatório
   */
  generateState() {
    const arr = new Uint8Array(20);
    crypto.getRandomValues(arr);
    return Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');
  },

  /**
   * Verifica se o usuário atual é admin antes de executar uma ação
   */
  requireAdmin(fn) {
    if (!Auth.isAdmin()) {
      Toast.show('Acesso negado.', 'error');
      return;
    }
    fn();
  },

  /**
   * Verifica se o usuário atual é dono de um servidor ou admin
   */
  requireOwnerOrAdmin(ownerId, fn) {
    const user = Auth.currentUser();
    if (!user) { Toast.show('Faça login primeiro.', 'error'); return; }
    if (user.id !== ownerId && user.type !== 'admin') {
      Toast.show('Sem permissão.', 'error');
      return;
    }
    fn();
  }
};

/* ============================================================
   4. AUTH / DISCORD OAUTH2
   ============================================================ */
const Auth = {
  currentUser() {
    return Storage.get(CONFIG.STORAGE_KEY.CURRENT_USER);
  },

  setCurrentUser(user) {
    Storage.set(CONFIG.STORAGE_KEY.CURRENT_USER, user);
  },

  isAdmin() {
    const u = this.currentUser();
    return u && u.type === 'admin';
  },

  isFile() {
    return window.location.protocol === 'file:';
  },

  getRedirectUri() {
    if (this.isFile()) return null;
    return window.location.origin + window.location.pathname;
  },

  login() {
    const redirectUri = this.getRedirectUri();

    if (!redirectUri) {
      const useFallback = confirm(
        '⚠️ Você abriu o site diretamente como arquivo (file://).\n\n' +
        'O Discord OAuth2 exige servidor web (ex: Live Server no VS Code).\n\n' +
        'Deseja usar o MODO DE TESTE? (login simulado)\n' +
        'Cancele para ver as instruções.'
      );
      if (useFallback) {
        this.simulateLogin();
      } else {
        alert(
          '🔧 Como rodar corretamente:\n\n' +
          '1. Instale "Live Server" no VS Code\n' +
          '2. Botão direito em index.html → "Open with Live Server"\n' +
          '3. Acesse http://127.0.0.1:5500/\n' +
          '4. No Discord Developer Portal → OAuth2 → Redirects,\n' +
          '   adicione: http://127.0.0.1:5500/index.html\n' +
          '5. Pronto!'
        );
      }
      return;
    }

    const state = Security.generateState();
    Storage.set(CONFIG.STORAGE_KEY.STATE, state);

    const params = new URLSearchParams({
      client_id: CONFIG.DISCORD_CLIENT_ID,
      redirect_uri: redirectUri,
      response_type: 'token',
      scope: 'identify email',
      state
    });

    window.location.href = `https://discord.com/oauth2/authorize?${params}`;
  },

  simulateLogin() {
    const fakeUser = {
      id: 'test_' + Date.now(),
      discordId: '000000000',
      name: 'Usuário Teste',
      email: 'teste@discord.com',
      avatar: 'https://cdn.discordapp.com/embed/avatars/1.png',
      type: 'user',
      createdAt: new Date().toISOString(),
      simulated: true
    };
    const users = Data.getUsers();
    users.push(fakeUser);
    Data.saveUsers(users);
    this.setCurrentUser(fakeUser);
    Nav.updateNav();
    Toast.show('Login simulado! Use Live Server para o login real.', 'info');
  },

  async handleCallback() {
    const hash = window.location.hash;
    if (!hash || !hash.includes('access_token')) return;

    const params = new URLSearchParams(hash.substring(1));
    const token = params.get('access_token');
    const state = params.get('state');
    const savedState = Storage.get(CONFIG.STORAGE_KEY.STATE);

    // Limpa URL e state CSRF
    history.replaceState(null, '', window.location.pathname);
    Storage.remove(CONFIG.STORAGE_KEY.STATE);

    if (!state || state !== savedState) {
      Toast.show('Erro de segurança no login. Tente novamente.', 'error');
      return;
    }

    if (!token) {
      const error = params.get('error_description') || params.get('error');
      if (error) Toast.show('Erro no login: ' + error, 'error');
      return;
    }

    await this.fetchDiscordUser(token);
  },

  async fetchDiscordUser(token) {
    try {
      const res = await fetch(`${CONFIG.DISCORD_API}/users/@me`, {
        headers: { Authorization: `Bearer ${token}` }
      });

      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const d = await res.json();

      const avatar = d.avatar
        ? `https://cdn.discordapp.com/avatars/${d.id}/${d.avatar}.png`
        : `https://cdn.discordapp.com/embed/avatars/${Number(d.discriminator || 0) % 5}.png`;

      const users = Data.getUsers();
      let user = users.find(u => u.discordId === d.id);

      if (!user) {
        user = {
          id: 'discord_' + d.id,
          discordId: d.id,
          name: Security.sanitizeText(d.global_name || d.username, 80),
          email: d.email || '',
          avatar,
          type: 'user',
          createdAt: new Date().toISOString()
        };
        users.push(user);
      } else {
        user.name   = Security.sanitizeText(d.global_name || d.username, 80);
        user.email  = d.email || user.email;
        user.avatar = avatar;
      }

      Data.saveUsers(users);
      this.setCurrentUser(user);
      Nav.updateNav();
      go('home');
      Toast.show(`Bem-vindo, ${user.name}!`, 'success');

    } catch (err) {
      console.error('Erro Discord OAuth:', err);
      Toast.show('Falha ao conectar com Discord. Tente novamente.', 'error');
    }
  },

  logout() {
    this.setCurrentUser(null);
    Nav.updateNav();
    go('home');
    Toast.show('Você saiu.', 'info');
  }
};

/* ============================================================
   5. DATA — gerenciamento de dados
   ============================================================ */
const Data = {
  getServers()       { return Storage.get(CONFIG.STORAGE_KEY.SERVERS, []); },
  saveServers(list)  { Storage.set(CONFIG.STORAGE_KEY.SERVERS, list); },
  getUsers()         { return Storage.get(CONFIG.STORAGE_KEY.USERS, []); },
  saveUsers(list)    { Storage.set(CONFIG.STORAGE_KEY.USERS, list); },
  getVotes()         { return Storage.get(CONFIG.STORAGE_KEY.VOTES, {}); },
  saveVotes(v)       { Storage.set(CONFIG.STORAGE_KEY.VOTES, v); },

  hasVoted(serverId) {
    const user = Auth.currentUser();
    const key = user ? user.id : 'guest_' + navigator.userAgent.slice(0, 32);
    const votes = this.getVotes();
    return Array.isArray(votes[key]) && votes[key].includes(serverId);
  },

  addVote(serverId) {
    const user = Auth.currentUser();
    const key = user ? user.id : 'guest_' + navigator.userAgent.slice(0, 32);
    const votes = this.getVotes();
    if (!votes[key]) votes[key] = [];
    if (!votes[key].includes(serverId)) votes[key].push(serverId);
    this.saveVotes(votes);
  }
};

/* ============================================================
   6. NAVEGAÇÃO
   ============================================================ */
let currentPage = 'home';

function go(page) {
  // Proteção: só admin pode ver o painel admin
  if (page === 'admin' && !Auth.isAdmin()) {
    Toast.show('Acesso restrito.', 'error');
    return;
  }
  // Proteção: só logado pode ver perfil
  if (page === 'profile' && !Auth.currentUser()) {
    Toast.show('Faça login para ver o perfil.', 'info');
    return;
  }

  document.querySelectorAll('.page').forEach(p => p.classList.remove('show'));
  const el = document.getElementById('page-' + page);
  if (!el) { console.warn('Página não encontrada:', page); return; }
  el.classList.add('show');
  window.scrollTo({ top: 0, behavior: 'smooth' });
  currentPage = page;

  // Atualiza link ativo no nav
  document.querySelectorAll('.nav-links a[data-page]').forEach(a => {
    a.classList.toggle('active', a.dataset.page === page);
  });

  if (page === 'home')    UI.Home.render();
  if (page === 'list')    UI.List.render();
  if (page === 'add')     UI.Form.render();
  if (page === 'profile') UI.Profile.render();
  if (page === 'admin')   UI.Admin.renderServers();
}

/* ============================================================
   7. UI — NAVBAR
   ============================================================ */
const Nav = {
  updateNav() {
    const user = Auth.currentUser();
    const guest  = document.getElementById('user-guest');
    const logged = document.getElementById('user-logged');
    const addBtn = document.getElementById('btn-add-nav');
    const adminLink = document.getElementById('admin-link');

    if (user) {
      guest.style.display  = 'none';
      logged.style.display = 'flex';
      if (addBtn) addBtn.style.display = 'inline-flex';
      const nameEl   = document.getElementById('user-name');
      const avatarEl = document.getElementById('user-avatar');
      if (nameEl)   nameEl.textContent = user.name;
      if (avatarEl) {
        avatarEl.src = user.avatar || CONFIG.PLACEHOLDER.ICON;
        avatarEl.alt = user.name;
      }
      if (adminLink) adminLink.style.display = user.type === 'admin' ? 'flex' : 'none';
    } else {
      guest.style.display  = 'block';
      logged.style.display = 'none';
      if (addBtn) addBtn.style.display = 'none';
    }
  }
};

function toggleUserMenu() {
  const btn  = document.getElementById('user-menu-btn');
  const drop = document.getElementById('user-dropdown');
  const open = drop.classList.toggle('show');
  btn.classList.toggle('open', open);
  btn.setAttribute('aria-expanded', open);
}

function toggleMenu() {
  const nav  = document.getElementById('nav-links');
  const btn  = document.getElementById('hamburger');
  const open = nav.classList.toggle('open');
  btn.classList.toggle('open', open);
  btn.setAttribute('aria-expanded', open);
}

function closeMenu() {
  document.getElementById('nav-links')?.classList.remove('open');
  document.getElementById('hamburger')?.classList.remove('open');
}

// Fecha dropdown ao clicar fora
document.addEventListener('click', e => {
  if (!e.target.closest('.user-wrap')) {
    document.getElementById('user-dropdown')?.classList.remove('show');
    document.getElementById('user-menu-btn')?.classList.remove('open');
  }
});

/* ============================================================
   8. HELPERS
   ============================================================ */
const CATS = {
  jogos: '🎮 JOGOS',
  programacao: '💻 PROGRAMAÇÃO',
  estudo: '📚 ESTUDO',
  entretenimento: '🎬 ENTRETENIMENTO',
  musica: '🎵 MÚSICA',
  arte: '🎨 ARTE',
  tecnologia: '🔧 TECNOLOGIA',
  outros: '📦 OUTROS'
};

function catName(c) {
  return CATS[c] || c || 'OUTROS';
}

function fmtDate(dateStr) {
  try { return new Date(dateStr).toLocaleDateString('pt-BR'); }
  catch { return '—'; }
}

/* ============================================================
   9. UI — CARDS
   ============================================================ */
function makeCard(s) {
  const user    = Auth.currentUser();
  const isAdmin = Auth.isAdmin();
  const isOwner = user && s.ownerId === user.id;

  const name = Security.escapeHtml(s.name);
  const desc = Security.escapeHtml(s.desc);
  const cat  = Security.escapeHtml(catName(s.cat));
  const sid  = Security.escapeHtml(s.id);

  const featuredBadge = s.featured ? `<div class="featured-badge">⭐ DESTAQUE</div>` : '';

  const bannerSrc = (s.banner && Security.isValidUrl(s.banner))
    ? Security.escapeHtml(s.banner)
    : CONFIG.PLACEHOLDER.BANNER;

  const iconSrc = (s.icon && Security.isValidUrl(s.icon))
    ? Security.escapeHtml(s.icon)
    : CONFIG.PLACEHOLDER.ICON;

  const linkHref = Security.isValidDiscordInvite(s.link)
    ? Security.escapeHtml(s.link)
    : '#';

  let adminActions = '';
  if (isAdmin) {
    adminActions = `
      <div class="card-admin-actions" onclick="event.stopPropagation()">
        <button class="btn-del" onclick="UI.Actions.deleteServer('${sid}')">EXCLUIR</button>
        <button class="btn-feature" onclick="UI.Actions.toggleFeature('${sid}')">
          ${s.featured ? 'REM. DESTAQUE' : 'DESTACAR'}
        </button>
      </div>`;
  } else if (isOwner) {
    adminActions = `
      <div class="card-admin-actions" onclick="event.stopPropagation()">
        <button class="btn-del" onclick="UI.Actions.deleteServer('${sid}')">EXCLUIR</button>
      </div>`;
  }

  return `
    <div class="card" onclick="UI.Detail.open('${sid}')">
      <div class="card-banner">
        ${featuredBadge}
        <img src="${bannerSrc}"
             onerror="this.src='${CONFIG.PLACEHOLDER.BANNER}'"
             alt="${name}">
      </div>
      <div class="card-body">
        <div class="card-top">
          <img src="${iconSrc}"
               onerror="this.src='${CONFIG.PLACEHOLDER.ICON}'"
               class="card-icon" alt="${name}">
          <div class="card-info">
            <h3 title="${name}">${name}</h3>
            <span class="cat">${cat}</span>
          </div>
        </div>
        <p>${desc}</p>
        <div class="card-stats">
          <span>👁 ${Number(s.views) || 0}</span>
          <span>❤️ ${Number(s.votes) || 0}</span>
          ${s.memberCount ? `<span>👥 ${s.memberCount}</span>` : ''}
        </div>
        <div class="card-btns" onclick="event.stopPropagation()">
          <button class="btn-view" onclick="UI.Detail.open('${sid}')">VER</button>
          <a href="${linkHref}" target="_blank" rel="noopener noreferrer" class="btn-enter">ENTRAR</a>
        </div>
        ${adminActions}
      </div>
    </div>`;
}

/* ============================================================
   10. UI — HOME
   ============================================================ */
const UI = {};

UI.Home = {
  CATEGORIES: [
    { id:'jogos',         icon:'🎮', name:'JOGOS' },
    { id:'programacao',   icon:'💻', name:'PROG.' },
    { id:'estudo',        icon:'📚', name:'ESTUDO' },
    { id:'entretenimento',icon:'🎬', name:'ENTRET.' },
    { id:'musica',        icon:'🎵', name:'MÚSICA' },
    { id:'arte',          icon:'🎨', name:'ARTE' },
    { id:'tecnologia',    icon:'🔧', name:'TECH' },
    { id:'outros',        icon:'📦', name:'OUTROS' }
  ],

  render() {
    const servers = Data.getServers();

    // Categorias
    document.getElementById('cats').innerHTML = this.CATEGORIES.map(c => `
      <div class="cat-card" onclick="UI.List.goCategory('${c.id}')">
        <span>${c.icon}</span>
        <p>${c.name}</p>
      </div>`
    ).join('');

    // Destaque
    const featuredEl = document.getElementById('featured');
    const featured = servers.filter(s => s.featured).sort((a,b) => b.votes - a.votes);
    featuredEl.innerHTML = featured.length
      ? featured.slice(0, 6).map(makeCard).join('')
      : '<p style="color:var(--text-muted);padding:24px 0">Nenhum servidor em destaque.</p>';

    // Mais votados
    const popularEl = document.getElementById('popular');
    const popular = [...servers].sort((a,b) => b.votes - a.votes);
    popularEl.innerHTML = popular.length
      ? popular.slice(0, 6).map(makeCard).join('')
      : '<p style="color:var(--text-muted);padding:24px 0">Nenhum servidor cadastrado ainda. Seja o primeiro!</p>';
  }
};

/* ============================================================
   11. UI — LISTA
   ============================================================ */
UI.List = {
  render() {
    const search = (document.getElementById('filter-search')?.value || '').toLowerCase().trim();
    const cat    = document.getElementById('filter-cat')?.value || '';
    const sort   = document.getElementById('filter-sort')?.value || 'votes';

    let list = Data.getServers();

    if (search) {
      list = list.filter(s =>
        s.name.toLowerCase().includes(search) ||
        s.desc.toLowerCase().includes(search) ||
        (Array.isArray(s.tags) && s.tags.some(t => t.toLowerCase().includes(search)))
      );
    }

    if (cat) list = list.filter(s => s.cat === cat);

    if (sort === 'votes') list.sort((a,b) => b.votes - a.votes);
    if (sort === 'new')   list.sort((a,b) => new Date(b.date) - new Date(a.date));
    if (sort === 'views') list.sort((a,b) => b.views - a.views);

    const grid  = document.getElementById('list-grid');
    const empty = document.getElementById('list-empty');

    if (list.length === 0) {
      grid.innerHTML = '';
      empty.style.display = 'block';
    } else {
      empty.style.display = 'none';
      grid.innerHTML = list.map(makeCard).join('');
    }
  },

  goCategory(cat) {
    go('list');
    const el = document.getElementById('filter-cat');
    if (el) { el.value = cat; }
    this.render();
  }
};

function renderList() { UI.List.render(); }

function doSearch(q) {
  if (!q || !q.trim()) return;
  go('list');
  const el = document.getElementById('filter-search');
  if (el) el.value = q.trim();
  UI.List.render();
}

function goCat(c) { UI.List.goCategory(c); }

/* ============================================================
   12. UI — DETALHE
   ============================================================ */
UI.Detail = {
  open(id) {
    const servers = Data.getServers();
    const s = servers.find(x => x.id === id);
    if (!s) return;

    // Incrementa views
    s.views = (s.views || 0) + 1;
    Data.saveServers(servers);

    const user    = Auth.currentUser();
    const isAdmin = Auth.isAdmin();
    const isOwner = user && s.ownerId === user.id;
    const isVoted = Data.hasVoted(id);

    const name = Security.escapeHtml(s.name);
    const desc = Security.escapeHtml(s.desc);
    const sid  = Security.escapeHtml(s.id);

    const bannerSrc = (s.banner && Security.isValidUrl(s.banner))
      ? Security.escapeHtml(s.banner) : CONFIG.PLACEHOLDER.BANNER;
    const iconSrc   = (s.icon && Security.isValidUrl(s.icon))
      ? Security.escapeHtml(s.icon) : CONFIG.PLACEHOLDER.ICON;
    const linkHref  = Security.isValidDiscordInvite(s.link)
      ? Security.escapeHtml(s.link) : '#';

    const tags = Array.isArray(s.tags)
      ? s.tags.map(t => `<span>#${Security.escapeHtml(t)}</span>`).join('')
      : '';

    let ownerSection = '';
    if (isOwner || isAdmin) {
      ownerSection = `
        <div class="detail-owner-actions">
          <p>🔧 ${isAdmin ? 'Admin' : 'Você é o dono'} — gerencie este servidor:</p>
          <button class="btn-del" onclick="UI.Actions.deleteServer('${sid}'); go('home')">EXCLUIR</button>
          ${isAdmin ? `<button class="btn-feature" onclick="UI.Actions.toggleFeature('${sid}'); UI.Detail.open('${sid}')">
            ${s.featured ? 'REMOVER DESTAQUE' : 'DESTACAR'}
          </button>` : ''}
        </div>`;
    }

    document.getElementById('detail-box').innerHTML = `
      <img src="${bannerSrc}" class="detail-banner"
           onerror="this.src='${CONFIG.PLACEHOLDER.BANNER}'" alt="${name}">
      <div class="detail-head">
        <img src="${iconSrc}" class="detail-icon"
             onerror="this.src='${CONFIG.PLACEHOLDER.ICON}'" alt="${name}">
        <div class="detail-title">
          <h1>${name}</h1>
          <div class="detail-meta">
            <span>${Security.escapeHtml(catName(s.cat))}</span>
            <span>👁 ${s.views} visualizações</span>
            <span>❤️ ${s.votes} votos</span>
            <span>📅 ${fmtDate(s.date)}</span>
          </div>
          <div class="detail-tags">${tags}</div>
        </div>
      </div>
      <p class="detail-desc">${desc}</p>
      <div class="detail-actions">
        <button class="btn-vote-d ${isVoted ? 'voted' : ''}"
                onclick="UI.Actions.vote('${sid}')"
                ${isVoted ? 'disabled' : ''}>
          ${isVoted ? '✓ VOTADO' : '❤️ VOTAR'}
        </button>
        <a href="${linkHref}" target="_blank" rel="noopener noreferrer" class="btn-join-d">
          🔗 ENTRAR NO SERVIDOR
        </a>
      </div>
      ${ownerSection}`;

    go('detail');
  }
};

function openDetail(id) { UI.Detail.open(id); }

/* ============================================================
   13. UI — AÇÕES (votar, excluir, destacar)
   ============================================================ */
UI.Actions = {
  vote(id) {
    if (Data.hasVoted(id)) return;
    const servers = Data.getServers();
    const s = servers.find(x => x.id === id);
    if (!s) return;
    s.votes = (s.votes || 0) + 1;
    Data.saveServers(servers);
    Data.addVote(id);
    Toast.show('Voto registrado! ❤️', 'success');
    UI.Detail.open(id);
  },

  deleteServer(id) {
    const user = Auth.currentUser();
    if (!user) { Toast.show('Sem permissão.', 'error'); return; }

    const servers = Data.getServers();
    const s = servers.find(x => x.id === id);
    if (!s) return;

    // Somente dono ou admin pode excluir
    if (user.id !== s.ownerId && user.type !== 'admin') {
      Toast.show('Você não tem permissão para excluir este servidor.', 'error');
      return;
    }

    if (!confirm(`Excluir "${s.name}"? Esta ação não pode ser desfeita.`)) return;

    const remaining = servers.filter(x => x.id !== id);
    Data.saveServers(remaining);

    // Limpa votos associados
    const votes = Data.getVotes();
    Object.keys(votes).forEach(k => {
      votes[k] = votes[k].filter(v => v !== id);
    });
    Data.saveVotes(votes);

    Toast.show('Servidor excluído.', 'info');

    if (currentPage === 'admin') UI.Admin.renderServers();
    else go('home');
  },

  toggleFeature(id) {
    Security.requireAdmin(() => {
      const servers = Data.getServers();
      const s = servers.find(x => x.id === id);
      if (!s) return;
      s.featured = !s.featured;
      Data.saveServers(servers);
      Toast.show(s.featured ? '⭐ Servidor destacado!' : 'Destaque removido.', 'success');
      if (currentPage === 'admin') UI.Admin.renderFeatured();
    });
  }
};

// Alias globais para uso inline no HTML
function doVote(id)          { UI.Actions.vote(id); }
function deleteServer(id)    { UI.Actions.deleteServer(id); }
function toggleFeature(id)   { UI.Actions.toggleFeature(id); }
function loginDiscord()      { Auth.login(); }
function logout()            { Auth.logout(); }

/* ============================================================
   14. UI — FORMULÁRIO (adicionar servidor)
   ============================================================ */
UI.Form = {
  render() {
    const user    = Auth.currentUser();
    const notice  = document.getElementById('add-login-notice');
    const formWrap = document.getElementById('form-add-wrap');
    if (!notice || !formWrap) return;

    if (!user) {
      notice.style.display   = 'flex';
      formWrap.style.display = 'none';
    } else {
      notice.style.display   = 'none';
      formWrap.style.display = 'block';
    }
  }
};

function submitServer() {
  const user = Auth.currentUser();
  if (!user) { Toast.show('Faça login primeiro.', 'error'); return; }

  // Coleta campos
  const name   = document.getElementById('f-name')?.value.trim()   || '';
  const desc   = document.getElementById('f-desc')?.value.trim()   || '';
  const link   = document.getElementById('f-link')?.value.trim()   || '';
  const cat    = document.getElementById('f-cat')?.value           || 'outros';
  const tags   = document.getElementById('f-tags')?.value.trim()   || '';
  const banner = document.getElementById('f-banner')?.value.trim() || '';
  const icon   = document.getElementById('f-icon')?.value.trim()   || '';

  // Validações
  if (!name)  { Toast.show('Informe o nome do servidor.', 'error'); return; }
  if (!desc)  { Toast.show('Informe a descrição.', 'error'); return; }
  if (!Security.isValidDiscordInvite(link)) {
    Toast.show('Link inválido. Use https://discord.gg/...', 'error');
    return;
  }
  if (banner && !Security.isValidUrl(banner)) {
    Toast.show('URL do banner inválida.', 'error'); return;
  }
  if (icon && !Security.isValidUrl(icon)) {
    Toast.show('URL do ícone inválida.', 'error'); return;
  }

  const server = {
    id: 'srv_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8),
    name:    Security.sanitizeText(name, 100),
    desc:    Security.sanitizeText(desc, 500),
    link:    link,
    cat:     cat,
    tags:    tags.split(',').map(t => Security.sanitizeText(t, 30)).filter(Boolean).slice(0, 10),
    banner:  banner,
    icon:    icon,
    votes:   0,
    views:   0,
    featured: false,
    ownerId:  user.id,
    ownerName: user.name,
    memberCount: 0,
    date: new Date().toISOString()
  };

  const list = Data.getServers();
  list.unshift(server);
  Data.saveServers(list);

  // Limpa form
  ['f-name','f-desc','f-link','f-tags','f-banner','f-icon'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });
  const countEl = document.getElementById('desc-count');
  if (countEl) countEl.textContent = '0/500';

  Toast.show('✅ Servidor publicado com sucesso!', 'success');
  go('home');
}

/* ============================================================
   15. UI — PERFIL
   ============================================================ */
UI.Profile = {
  render() {
    const user = Auth.currentUser();
    if (!user) { go('home'); return; }

    const avatar = document.getElementById('profile-avatar');
    const nameEl = document.getElementById('profile-name');
    const emailEl = document.getElementById('profile-email');
    const roleEl  = document.getElementById('profile-role');
    const srvEl   = document.getElementById('profile-servers');
    const votesEl = document.getElementById('profile-votes');
    const grid    = document.getElementById('profile-servers-grid');

    if (avatar) avatar.src = user.avatar || CONFIG.PLACEHOLDER.ICON;
    if (nameEl)  nameEl.textContent = user.name;
    if (emailEl) emailEl.textContent = user.email || '';
    if (roleEl) {
      roleEl.textContent = user.type === 'admin' ? 'ADMINISTRADOR' : 'USUÁRIO';
      roleEl.className   = 'role-badge ' + user.type;
    }

    const myServers = Data.getServers().filter(s => s.ownerId === user.id);
    if (srvEl)   srvEl.textContent = myServers.length;
    if (votesEl) votesEl.textContent = (Data.getVotes()[user.id] || []).length;

    if (grid) {
      grid.innerHTML = myServers.length
        ? myServers.map(makeCard).join('')
        : '<p style="color:var(--text-muted)">Você ainda não divulgou nenhum servidor.</p>';
    }
  }
};

/* ============================================================
   16. UI — ADMIN
   ============================================================ */
UI.Admin = {
  renderServers() {
    if (!Auth.isAdmin()) return;

    const search  = (document.getElementById('admin-search')?.value || '').toLowerCase();
    const filter  = document.getElementById('admin-filter')?.value || '';
    let list = Data.getServers();

    if (search) list = list.filter(s => s.name.toLowerCase().includes(search));
    if (filter === 'featured') list = list.filter(s => s.featured);

    const tbody = document.querySelector('#admin-servers-table tbody');
    if (!tbody) return;

    tbody.innerHTML = list.map(s => {
      const name = Security.escapeHtml(s.name);
      const sid  = Security.escapeHtml(s.id);
      const tags = Array.isArray(s.tags) ? s.tags.map(t => Security.escapeHtml(t)).join(', ') : '';
      const iconSrc = (s.icon && Security.isValidUrl(s.icon)) ? Security.escapeHtml(s.icon) : '';
      return `
        <tr>
          <td>
            <div class="server-cell">
              <img src="${iconSrc}" onerror="this.style.display='none'" alt="">
              <div>
                <div>${name}</div>
                <small>${tags}</small>
              </div>
            </div>
          </td>
          <td>${Security.escapeHtml(catName(s.cat))}</td>
          <td>${s.votes}</td>
          <td>${s.views}</td>
          <td>${Security.escapeHtml(s.ownerName || '—')}</td>
          <td>${fmtDate(s.date)}</td>
          <td>
            <button class="btn-table feature"
                    onclick="UI.Actions.toggleFeature('${sid}'); UI.Admin.renderServers()">
              ${s.featured ? 'Remover' : 'Destacar'}
            </button>
            <button class="btn-table del"
                    onclick="UI.Actions.deleteServer('${sid}'); UI.Admin.renderServers()">
              Excluir
            </button>
          </td>
        </tr>`;
    }).join('');
  },

  renderUsers() {
    if (!Auth.isAdmin()) return;

    const search = (document.getElementById('admin-user-search')?.value || '').toLowerCase();
    let users = Data.getUsers();
    if (search) users = users.filter(u =>
      u.name.toLowerCase().includes(search) ||
      (u.email && u.email.toLowerCase().includes(search))
    );

    const tbody = document.querySelector('#admin-users-table tbody');
    if (!tbody) return;

    tbody.innerHTML = users.map(u => {
      const srvCount  = Data.getServers().filter(s => s.ownerId === u.id).length;
      const voteCount = (Data.getVotes()[u.id] || []).length;
      const uid       = Security.escapeHtml(u.id);
      const name      = Security.escapeHtml(u.name);
      const did       = Security.escapeHtml(u.discordId || u.id);
      const avatarSrc = (u.avatar && Security.isValidUrl(u.avatar)) ? Security.escapeHtml(u.avatar) : '';
      return `
        <tr>
          <td>
            <div class="server-cell">
              <img src="${avatarSrc}" onerror="this.style.display='none'" alt="">
              <div>${name}</div>
            </div>
          </td>
          <td><code style="font-size:0.72rem;color:var(--text-muted)">${did}</code></td>
          <td><span class="role-badge ${u.type}">${u.type.toUpperCase()}</span></td>
          <td>${srvCount}</td>
          <td>${voteCount}</td>
          <td>${fmtDate(u.createdAt)}</td>
          <td>
            <button class="btn-table edit" onclick="UI.Admin.promoteUser('${uid}')">
              ${u.type === 'admin' ? 'Rebaixar' : 'Promover'}
            </button>
            <button class="btn-table del" onclick="UI.Admin.deleteUser('${uid}')">Excluir</button>
          </td>
        </tr>`;
    }).join('');
  },

  renderFeatured() {
    if (!Auth.isAdmin()) return;

    const search = (document.getElementById('admin-featured-search')?.value || '').toLowerCase();
    let list = Data.getServers();
    if (search) list = list.filter(s => s.name.toLowerCase().includes(search));

    const grid = document.getElementById('admin-featured-grid');
    if (!grid) return;

    grid.innerHTML = list.map(s => {
      const sid = Security.escapeHtml(s.id);
      return `
        <div>
          ${makeCard(s)}
          <div style="padding:0 0 12px">
            <button class="btn-feature" style="width:100%;padding:8px"
                    onclick="UI.Actions.toggleFeature('${sid}'); UI.Admin.renderFeatured()">
              ${s.featured ? 'REMOVER DESTAQUE' : 'COLOCAR EM DESTAQUE'}
            </button>
          </div>
        </div>`;
    }).join('');
  },

  promoteUser(id) {
    Security.requireAdmin(() => {
      const users = Data.getUsers();
      const u = users.find(x => x.id === id);
      if (!u) return;
      u.type = u.type === 'admin' ? 'user' : 'admin';
      Data.saveUsers(users);

      // Atualiza sessão se for o usuário atual
      const current = Auth.currentUser();
      if (current && current.id === id) {
        Auth.setCurrentUser(u);
        Nav.updateNav();
      }
      Toast.show(u.type === 'admin' ? 'Usuário promovido a Admin.' : 'Usuário rebaixado.', 'info');
      this.renderUsers();
    });
  },

  deleteUser(id) {
    Security.requireAdmin(() => {
      const users = Data.getUsers();
      const u = users.find(x => x.id === id);
      if (!u) return;
      if (!confirm(`Excluir usuário "${u.name}" e todos os seus servidores?`)) return;

      Data.saveServers(Data.getServers().filter(s => s.ownerId !== id));
      Data.saveUsers(users.filter(x => x.id !== id));
      Toast.show('Usuário excluído.', 'info');
      this.renderUsers();
    });
  }
};

// Alias para HTML inline
function renderAdminServers()  { UI.Admin.renderServers(); }
function renderAdminUsers()    { UI.Admin.renderUsers(); }
function renderAdminFeatured() { UI.Admin.renderFeatured(); }
function promoteUser(id)       { UI.Admin.promoteUser(id); }
function deleteUser(id)        { UI.Admin.deleteUser(id); }

function switchTab(tab, btn) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.style.display = 'none');
  if (btn) btn.classList.add('active');
  const el = document.getElementById('tab-' + tab);
  if (el) el.style.display = 'block';
  if (tab === 'servers')  UI.Admin.renderServers();
  if (tab === 'users')    UI.Admin.renderUsers();
  if (tab === 'featured') UI.Admin.renderFeatured();
}

/* ============================================================
   17. TOAST — notificações
   ============================================================ */
const Toast = {
  show(msg, type = 'info', duration = 3500) {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const icons = { success: '✅', error: '❌', info: 'ℹ️' };
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `<span>${icons[type] || 'ℹ️'}</span> ${Security.escapeHtml(msg)}`;
    container.appendChild(toast);

    setTimeout(() => {
      toast.style.animation = 'toastIn 0.25s ease reverse';
      setTimeout(() => toast.remove(), 250);
    }, duration);
  }
};

/* ============================================================
   18. CONTADOR DE CARACTERES
   ============================================================ */
document.addEventListener('input', e => {
  if (e.target.id === 'f-desc') {
    const count = document.getElementById('desc-count');
    if (count) count.textContent = `${e.target.value.length}/500`;
  }
});

/* ============================================================
   19. INIT
   ============================================================ */
document.addEventListener('DOMContentLoaded', () => {
  Nav.updateNav();
  UI.Home.render();
  Auth.handleCallback();

  if (window.location.protocol === 'file:') {
    console.warn(
      '%c⚠️ GERAL DIVULGAÇÃO',
      'color:#f9a825;font-weight:bold;font-size:14px',
      '\nOAuth2 do Discord NÃO funciona com file://\n' +
      'Use Live Server (VS Code) ou hospede online.\n' +
      'Adicione o redirect no Discord Developer Portal.'
    );
  }
});