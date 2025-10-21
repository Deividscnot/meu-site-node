// PARTE 1 - CONFIGURAÇÕES, MIDDLEWARES E AUTENTICAÇÃO
require('dotenv').config();

const express = require('express');
const path = require('path');
const fs = require('fs').promises;
const fsSync = require('fs');
const bcrypt = require('bcrypt');
const session = require('express-session');
const multer = require('multer');
const { payload: generatePixPayload } = require('pix-payload');
const QRCode = require('qrcode');
const TelegramBot = require('node-telegram-bot-api');

const app = express();
const port = process.env.PORT || 3010;

const FILE_TOKEN_COST = 80;
const DATA_DIR = path.join(__dirname, 'data');
const PENDENTES_FILE = path.join(__dirname, 'pendentes.json');

// --- utils pendentes PIX ---
function loadPendentes() {
  if (!fsSync.existsSync(PENDENTES_FILE)) return [];
  return JSON.parse(fsSync.readFileSync(PENDENTES_FILE, 'utf8'));
}
function savePendentes(list) {
  fsSync.writeFileSync(PENDENTES_FILE, JSON.stringify(list, null, 2));
}

// estáticos e parsers
app.use('/static', express.static(path.join(__dirname, 'public')));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use((req, res, next) => {
  res.setHeader('ngrok-skip-browser-warning', 'true');
  next();
});

// views
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// sessão
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false },
}));

app.post('/aceitar-termo', (req, res) => {
  req.session.termoAceitoAt = Date.now();

  // Se veio com JSON (fetch da home), responde JSON:
  if (req.is('application/json')) {
    return res.json({ ok: true });
  }

  // Se veio de um <form> (text/html), redireciona:
  // Se o referer era /termo(s), vamos direto pro login; caso contrário, volta pra home.
  const ref = String(req.get('referer') || '');
  const goLogin = ref.includes('/termo');
  return res.redirect(goLogin ? '/login' : '/');
});
function exigeTermo(req, res, next) {
  if (req.session && req.session.termoAceitoAt) return next();
  return res.redirect('/?termo=obrigatorio');
}

// upload
const upload = multer({ dest: path.join(__dirname, 'uploads') });

// "db" de usuários simples em arquivo
function loadUsers() {
  const file = path.join(__dirname, 'usuarios.json');
  if (!fsSync.existsSync(file)) return [];
  return JSON.parse(fsSync.readFileSync(file, 'utf8'));
}
function saveUsers(users) {
  fsSync.writeFileSync(path.join(__dirname, 'usuarios.json'), JSON.stringify(users, null, 2));
}
function getUser(username) {
  return loadUsers().find(u => u.username === username);
}
function updateUser(username, updates) {
  const users = loadUsers();
  const idx = users.findIndex(u => u.username === username);
  if (idx !== -1) {
    users[idx] = { ...users[idx], ...updates };
    saveUsers(users);
  }
}
function requireLogin(req, res, next) {
  if (req.session?.user) return next();
  res.redirect('/login');
}

// Router opcional de airbags
try {
  const airbagsRouter = require('./data/airbags');
  app.use('/airbags', airbagsRouter);
} catch (_) {
  // ignora se não houver
}

// Telegram bot (opcional)
const botToken = process.env.TELEGRAM_BOT_TOKEN;
let bot = null;
if (botToken) {
  bot = new TelegramBot(botToken, { polling: true });
}

/* ============================
   AUTH ROUTES (ATUALIZADAS)
   ============================ */

// LOGIN
app.get('/login', exigeTermo, (req, res) => res.render('login', { error: null }));

app.post('/login', exigeTermo, (req, res) => {
  const usernameInput = (req.body.username || '').toLowerCase().trim();
  const { password } = req.body;

  const u = getUser(usernameInput);
  if (u && bcrypt.compareSync(password, u.passwordHash)) {
    const lastLoginAt = new Date().toISOString();
    updateUser(u.username, { lastLoginAt });
    req.session.user = { ...u, lastLoginAt };
    return res.redirect('/painel'); // após login vai pro painel
  }
  res.render('login', { error: 'Usuário ou senha inválidos' });
});

// REGISTER (CADASTRO COMPLETO)
app.get('/register', exigeTermo, (req, res) => res.render('register', { error: null }));

app.post('/register', exigeTermo, (req, res) => {
  const {
    fullName, email, password, password2,
    whatsapp, company, city, state, doc, source, accept,
    username: legacyUsername
  } = req.body;

  const isNewForm = !!email;

  if (isNewForm) {
    if (!fullName || !email || !password || !password2 || !whatsapp || !city || !state) {
      return res.render('register', { error: 'Preencha todos os campos obrigatórios (*)' });
    }
    const emailOk = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email).trim());
    if (!emailOk) return res.render('register', { error: 'E-mail inválido' });
    if (String(password).length < 8) return res.render('register', { error: 'A senha deve ter pelo menos 8 caracteres' });
    if (password !== password2) return res.render('register', { error: 'As senhas não conferem' });
    if (!accept) return res.render('register', { error: 'É necessário aceitar os Termos de Uso' });

    const username = String(email).toLowerCase().trim();
    const users = loadUsers();
    if (users.find(u => u.username === username)) {
      return res.render('register', { error: 'Já existe uma conta com este e-mail' });
    }

    const hash = bcrypt.hashSync(password, 10);
    const newUser = {
      username,
      email: username,
      fullName: String(fullName).trim(),
      whatsapp: String(whatsapp).trim(),
      company: String(company || '').trim(),
      city: String(city).trim(),
      state: String(state).trim(),
      doc: String(doc || '').trim(),
      source: String(source || '').trim(),
      passwordHash: hash,
      tokens: 0,
      role: 'client',
      status: 'active',
      createdAt: new Date().toISOString(),
      acceptedTermsAt: new Date().toISOString(),
      lastLoginAt: null
    };

    users.push(newUser);
    saveUsers(users);

    req.session.user = newUser;
    return res.redirect('/painel');

  } else {
    const username = String(legacyUsername || '').toLowerCase().trim();
    const pwd = String(req.body.password || '');
    if (!username || !pwd) {
      return res.render('register', { error: 'Informe usuário e senha.' });
    }
    const users = loadUsers();
    if (users.find(u => u.username === username)) {
      return res.send('Usuário já existe. <a href="/register">Voltar</a>');
    }
    const hash = bcrypt.hashSync(pwd, 10);
    users.push({
      username,
      email: username,
      fullName: '',
      whatsapp: '',
      company: '',
      city: '',
      state: '',
      doc: '',
      source: '',
      passwordHash: hash,
      tokens: 0,
      role: 'client',
      status: 'active',
      createdAt: new Date().toISOString(),
      acceptedTermsAt: null,
      lastLoginAt: null
    });
    saveUsers(users);
    return res.redirect('/login');
  }
});

app.get('/logout', (req, res) => req.session.destroy(() => res.redirect('/login')));

/* =======================
   PÁGINAS PÚBLICAS
   ======================= */

// HOME pública (landing). Se logado, manda pro painel.
app.get('/', (req, res) => {
  if (req.session?.user) return res.redirect('/painel');
  
  // Teste de deploy Railway
  res.send('<h1>🚀 Versão Nova — Railway Teste 21/10/2025</h1>');
});

// Sobre / Produtos / Termos (GET) — públicos
app.get('/sobre', (req, res) => res.render('sobre'));
app.get('/produtos', (req, res) => res.render('produtos'));
app.get('/termo', (req, res) => res.render('termo'));
app.get('/termos', (req, res) => res.render('termo')); // alias para evitar 404

/* =======================
   ÁREA INTERNA / PAINEL
   ======================= */

const DEFAULT_MODEL = 'titan160';

// Painel interno (somente logado)
app.get('/painel', requireLogin, (req, res) => {
  const user = getUser(req.session.user.username);
  const selectedModel = req.session.selectedModel || DEFAULT_MODEL;
  res.render('painel', {
    user,
    session: req.session,
    currentKm: null,
    message: null,
    selectedModel
  });
});

// Atalho que renderiza o mesmo painel (se você usa esse caminho no front)
app.get('/alterar-km', requireLogin, (req, res) => {
  const user = getUser(req.session.user.username);
  const selectedModel = req.session.selectedModel || DEFAULT_MODEL;
  res.render('painel', { user, currentKm: null, message: null, session: req.session, selectedModel });
});

/* =======================
   CONVERSÕES E MAPAS
   ======================= */
const BROZ_FACTOR = 0.64;
const KM_WRAP_XRE = 1_000_000;

const DEFAULT_FACTOR = 0.031; // fallback legado
const MODEL_FACTORS = {
  titan160:          0.03125428035171639,
  xre190:            0.03125428035171639,
  xre300_2018_93c66: 0.03125428035171639, 
  crosser150:        0.03125428035171639,
  factor15093c66:    0.03125428035171639,
  biz2018:           0.03125428035171639,
  cb500x2023:        0.03125428035171639,
};
function getFactor(model) {
  return MODEL_FACTORS[model] ?? DEFAULT_FACTOR;
}
function convertBrozToEepromBytes(km) {
  const valor = Math.round(km * BROZ_FACTOR);
  const buf = Buffer.alloc(2);
  buf.writeUInt16LE(valor, 0);
  return buf;
}
function convertMileageToEepromBytesFor(model, km) {
  const f = getFactor(model);
  const valor = Math.floor(km * f);
  const comp = 0xFFFF - valor;
  const buf = Buffer.alloc(4);
  buf.writeUInt16LE(valor, 0);
  buf.writeUInt16LE(comp, 2);
  return buf;
}

const mileageLocations = {
  titan160: [0x0098,0x009C,0x00A0,0x00A4,0x00A8,0x00AC,0x00B0,0x00B4,0x00B8,0x00BC,0x00C0,0x00C4,0x00C8,0x00CC,0x00D0,0x00D4,0x00D8,0x00DA,0x00DE,0x00E0,0x00E2],
  biz2018: [0x005C,0x0060,0x0064,0x0068,0x006C,0x0070,0x0074,0x0078,0x007C,0x0080,0x0084,0x0088,0x008C,0x0098],
  cb500x2023: [0x0100,0x0104,0x0108,0x010C,0x0110,0x0114,0x0118,0x011C,0x0120,0x0124,0x0128,0x012C,0x0130,0x0134,0x0138,0x013C],
  crosser150: [0x00A0,0x00A4,0x00A8,0x00B0,0x00B4,0x00B8,0x00C0,0x00C4,0x00C8,0x00D0,0x00D4,0x00D8],
  broz24C04: [0x01B2,0x01C2,0x01D2,0x01E2],
  cb300: [0x0080,0x0090,0x00C0,0x00D0],
  cbtwister24c02: [0x0004],
  tornado24c02: [0x0005],
  xt66024c02: [0x0028,0x0030,0x0040,0x0050,0x0060,0x0070],
  xre190: [0x0098,0x009C,0x00A0,0x00A4,0x00A8,0x00AC,0x00B0,0x00B4,0x00B8,0x00BC,0x00C0,0x00C4,0x00C8,0x00CC,0x00D0,0x00D4,0x00D8,0x00DA,0x00DE,0x00E0,0x00E2],
  xre300_2014_24c02: [0x0004],
   xre300_2018_93c66: [0x00A0,0x00A4,0x00A8,0x00B0,0x00B4,0x00B8,0x00C0,0x00C4,0x00C8,0x00D0,0x00D4,0x00D8], 
  factor15093c66: [0x00A0,0x00A4,0x00A8,0x00B0,0x00B4,0x00B8,0x00C0,0x00C4,0x00C8,0x00D0,0x00D4,0x00D8],
};

function getModelConfig(model) {
  const cfg = {
    titan160:           { template: 'titan160.bin',        offsets: mileageLocations.titan160 },
    xre190:             { template: 'xre190.bin',          offsets: mileageLocations.xre190 },
    biz2018:            { template: 'biz2018.bin',         offsets: mileageLocations.biz2018 },
    cb500x2023:         { template: 'cb500x2023.bin',      offsets: mileageLocations.cb500x2023 },
    crosser150:         { template: 'crosser150_base.bin', offsets: mileageLocations.crosser150 },
    broz24C04:          { template: 'broz24C04.bin',       offsets: mileageLocations.broz24C04 },
    cbtwister24c02:     { template: 'cbtwister24c02.bin',  offsets: mileageLocations.cbtwister24c02 },
    tornado24c02:       { template: 'tornado24c02.bin',    offsets: mileageLocations.tornado24c02 },
    xt66024c02:         { template: 'xt66024c02.bin',      offsets: mileageLocations.xt66024c02 },
    cb300:              { template: 'cb300_base.bin',      offsets: mileageLocations.cb300 },
    xre300_2014_24c02:  { template: 'xre300_2014_24c02.bin', offsets: mileageLocations.xre300_2014_24c02 },
    xre300_2018_93c66:  { template: 'xre300_2018_93c66.bin', offsets: mileageLocations.xre300_2018_93c66 },
    factor15093c66:     { template: 'factor15093c66.bin',  offsets: mileageLocations.factor15093c66 },
  }[model];
  if (!cfg) throw new Error(`Modelo inválido: ${model}`);
  return cfg;
}

/* =======================
   ROTAS PRINCIPAIS (KM)
   ======================= */

// LEITURA DE KM/VALOR
app.post('/ler-km', requireLogin, upload.single('binfile'), async (req, res) => {
  const user = getUser(req.session.user.username);
  try {
    if (!req.file) throw new Error('Nenhum arquivo enviado.');
    const buf = await fs.readFile(req.file.path);
    await fs.unlink(req.file.path);

    const model = req.body.model;
    if (!model) throw new Error('Modelo não informado.');
    req.session.selectedModel = model;

    let km = null;

    if (model === 'xre300_2014_24c02') {
      if (buf.length < 0x0062) throw new Error('Arquivo menor que o esperado para 24C02.');
      const enc = buf.readUInt16LE(0x0008);
      let kmCalc = Math.round(enc * 19.2);
      if (kmCalc >= KM_WRAP_XRE) kmCalc -= KM_WRAP_XRE;
      km = kmCalc;

    } else if (model === 'tornado24c02') {
      const base = 0x0005, step = 4, reps = 12;
      const vals = [];
      for (let i = 0; i < reps; i++) {
        const off = base + step * i;
        if (off + 1 >= buf.length) break;
        vals.push(buf.readUInt16LE(off));
      }
      if (!vals.length) throw new Error('Arquivo menor que o esperado para Tornado 24C02.');
      const freq = vals.reduce((m,v)=> (m[v]=(m[v]||0)+1, m), {});
      const enc = Number(Object.entries(freq).sort((a,b)=>b[1]-a[1])[0][0]);
      km = Math.round(enc * 25.6);

    } else if (model === 'cbtwister24c02') {
      if (buf.length < 8) throw new Error('Arquivo menor que o esperado para 24C02.');
      const raw = buf.readUInt16LE(0x0004);
      km = Math.round(raw / 3.4464);

    } else if (model === 'broz24C04') {
      const { offsets } = getModelConfig(model);
      let raw = null;
      for (const off of offsets) {
        if (off + 2 <= buf.length) { raw = buf.readUInt16LE(off); break; }
      }
      if (raw === null) throw new Error('Nenhum offset válido para Broz 24C04.');
      km = Math.round(raw / BROZ_FACTOR);

    } else if (model === 'xt66024c02') {
      const bcdToDec = b => (((b >> 4) & 0xF) * 10) + (b & 0xF);
      const valsB1 = [], valsB2 = [];
      for (let addr = 0x0028; addr <= 0x0078; addr += 8) {
        if (addr + 7 >= buf.length) break;
        valsB1.push(buf[addr + 1]);
        const b2a = buf[addr + 2];
        const b2b = buf[addr + 7];
        valsB2.push(b2a === 0xFF ? b2b : b2a);
      }
      if (!valsB1.length || !valsB2.length) throw new Error('Área da XT660 ausente/corrompida.');
      const freq = arr => arr.reduce((m,v)=> (m[v]=(m[v]||0)+1, m), {});
      const top = o => Number(Object.entries(o).sort((a,b)=>b[1]-a[1])[0][0]);
      const B1 = top(freq(valsB1)) & 0xFF;
      const B2 = top(freq(valsB2)) & 0xFF;
      km = bcdToDec(B2) * 1000 + bcdToDec(B1) * 10;

    } else if (['titan160','xre190','xre300_2018_93c66','biz2018','cb500x2023','cb300','crosser150','factor15093c66'].includes(model)) {
      const { offsets } = getModelConfig(model);
      let raw = null;
      for (const off of offsets) {
        if (off + 4 > buf.length) continue;
        const v = buf.readUInt16LE(off);
        const c = buf.readUInt16LE(off + 2);
        if ((v + c) === 0xFFFF) { raw = v; break; }
      }
      if (raw === null) throw new Error('Nenhum offset válido para este modelo.');
      km = Math.round(raw / getFactor(model));

    } else {
      throw new Error(`Modelo não suportado na leitura: ${model}`);
    }

    if (req.headers['x-fetch-json'] === '1') {
      return res.json({ modelo: model, km });
    }
    res.render('painel', { user, currentKm: km, message: null, session: req.session, selectedModel: req.session.selectedModel });

  } catch (err) {
    if (req.headers['x-fetch-json'] === '1') {
      return res.status(400).json({ error: err.message });
    }
    res.render('painel', { user, session: req.session, currentKm: null, message: `Erro: ${err.message}`, selectedModel: req.session.selectedModel });
  }
});

// GERAR E BAIXAR TEMPLATE/BIN
app.post('/alterar-e-baixar-template', requireLogin, async (req, res) => {
  try {
    const kmRaw = parseInt(req.body.new_mileage, 10);
    const model = req.body.model;
    if (isNaN(kmRaw) || kmRaw < 0) throw new Error('KM inválido');
    if (!model) throw new Error('Modelo não informado.');
    req.session.selectedModel = model;

    const userBefore = getUser(req.session.user.username);
    if ((userBefore.tokens || 0) < FILE_TOKEN_COST) {
      return res.render('insufficient', { cost: FILE_TOKEN_COST });
    }
    updateUser(userBefore.username, { tokens: (userBefore.tokens || 0) - FILE_TOKEN_COST });
    const userAfter = getUser(userBefore.username);
    req.session.user = userAfter;

    const { template, offsets } = getModelConfig(model);

    let buffer;
    try {
      const original = await fs.readFile(path.join(DATA_DIR, template));
      buffer = Buffer.from(original);
    } catch (e) {
      const is24c02 = (
        model === 'cbtwister24c02' ||
        model === 'xre300_2014_24c02' ||
        model === 'tornado24c02' ||
        model === 'xt66024c02'
      );
      if (e.code === 'ENOENT' && is24c02) {
        buffer = Buffer.alloc(256, 0xFF);
      } else {
        throw new Error(`Template ausente: coloque "${template}" em "${DATA_DIR}".`);
      }
    }

    if (model === 'broz24C04') {
      const val = Math.round(kmRaw * BROZ_FACTOR);
      for (const off of offsets) if (off + 2 <= buffer.length) buffer.writeUInt16LE(val, off);

    } else if (model === 'tornado24c02') {
      if (kmRaw > 99999) throw new Error('Máximo permitido: 99.999 km para Tornado 24C02');
      const enc = Math.floor(kmRaw / 25.6);
      if (enc < 0 || enc > 0xFFFF) throw new Error('KM fora do alcance para Tornado 24C02.');
      const base = 0x0005, step = 4, reps = 12;
      for (let i = 0; i < reps; i++) {
        const off = base + step * i;
        if (off + 1 >= buffer.length) break;
        buffer.writeUInt16LE(enc, off);
      }
      for (let i = 0; i < reps; i++) {
        const aOff = 0x0004 + step * i;
        const vOff = 0x0005 + step * i;
        const cOff = 0x0007 + step * i;
        if (aOff < buffer.length && buffer[aOff] === 0xFF) buffer[aOff] = 0xA0 + i;
        if (cOff < buffer.length && vOff + 1 < buffer.length) {
          const sum = (buffer[aOff] + buffer[vOff] + buffer[vOff + 1]) & 0xFF;
          buffer[cOff] = (0x100 - sum) & 0xFF;
        }
      }

    } else if (model === 'cbtwister24c02' || model === 'xre300_2014_24c02') {
      const valor = (model === 'xre300_2014_24c02')
        ? Math.floor((((kmRaw % KM_WRAP_XRE) + KM_WRAP_XRE) % KM_WRAP_XRE) / 19.2)
        : Math.round(kmRaw * 3.4464);

      if (valor > 0xFFFF) {
        const maxKm = (model === 'xre300_2014_24c02') ? (KM_WRAP_XRE - 1) : 99999;
        throw new Error(`KM muito alto para ${model}. Máximo ≈ ${maxKm} km`);
      }

      if (model === 'xre300_2014_24c02') {
        for (let p = 0x0008; p <= 0x0060; p += 8) {
          if (p + 1 < buffer.length) buffer.writeUInt16LE(valor, p);
          if (p + 3 < buffer.length) buffer.writeUInt16LE(valor, p + 2);
        }
      } else {
        buffer.writeUInt16LE(valor, 0x0004);
        buffer.writeUInt16LE(0xFFFF, 0x0006);
        for (let i = 0x0008; i <= 0x0033; i++) buffer[i] = 0xFF;
      }

    } else if (model === 'xt66024c02') {
      const toBcd = d => {
        const tens = Math.floor(d / 10) % 10;
        const ones = d % 10;
        return ((tens << 4) | ones) & 0xFF;
      };
      const kmNorm = Math.max(0, Math.round(kmRaw / 10) * 10);
      const thousands = Math.floor(kmNorm / 1000);
      const tens = Math.floor((kmNorm % 1000) / 10);
      const B2 = toBcd(Math.min(99, thousands));
      const B1 = toBcd(Math.min(99, tens));
      if (buffer.length < 0x80) {
        throw new Error('Arquivo menor que o esperado para 24C02 (>= 0x80 bytes).');
      }
      for (let addr = 0x0028; addr <= 0x0078; addr += 8) {
        if (addr + 7 >= buffer.length) break;
        buffer[addr + 0] = 0x00;
        buffer[addr + 1] = B1;
        buffer[addr + 2] = B2;
        buffer[addr + 3] = 0x00;
        buffer[addr + 4] = 0x00;
        buffer[addr + 5] = 0x00;
        buffer[addr + 6] = 0x00;
        buffer[addr + 7] = B2;
      }

    } else if (model === 'biz2018') {
      const kmBytes = convertMileageToEepromBytesFor('biz2018', kmRaw);
      for (let i = 0x005C; i <= 0x009B; i += 4) {
        if (i + 3 < buffer.length) kmBytes.copy(buffer, i);
      }

    } else {
      const kmBytes = convertMileageToEepromBytesFor(model, kmRaw);
      const { offsets } = getModelConfig(model);
      for (const off of offsets) if (off + 4 <= buffer.length) kmBytes.copy(buffer, off);
    }

    res.setHeader('Content-Disposition', `attachment; filename="${model}_${kmRaw}km.bin"`);
    res.setHeader('Content-Type', 'application/octet-stream');
    return res.send(buffer);

  } catch (err) {
    res.status(500).send(`Erro interno: ${err.message}`);
  }
});

/* =======================
   PIX / TOKENS
   ======================= */

app.get('/comprar-tokens', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'comprar.html'));
});

app.get('/pix-qrcode', requireLogin, async (req, res) => {
  const valor = parseFloat(req.query.valor);
  const txid = req.query.txid;
  if (!valor || !txid) return res.status(400).send('Parâmetros faltando.');
  try {
    const pix = generatePixPayload({
      key: process.env.PIX_KEY,
      name: process.env.PIX_NAME,
      city: process.env.PIX_CITY || '',
      amount: valor,
      transactionId: txid,
    });
    const qrImageUrl = await QRCode.toDataURL(pix);
    res.json({ payload: pix, qrImageUrl, txid, valor });
  } catch (err) {
    res.status(500).send(`Erro ao gerar QR Code: ${err.message}`);
  }
});

app.post('/confirmar-pix', requireLogin, async (req, res) => {
  const { valor, txid } = req.body;
  const user = getUser(req.session.user.username);
  const pend = loadPendentes();
  pend.push({ txid, username: user.username, valor, timestamp: Date.now() });
  savePendentes(pend);

  if (bot) {
    const text = `*Novo PIX aguardando comprovante*\n` +
      `• Usuário: _${user.username}_\n` +
      `• Tokens: *+${valor}*\n` +
      `• TXID: \`${txid}\``;
    const opts = {
      parse_mode: 'Markdown',
      reply_markup: {
        inline_keyboard: [[{ text: '✅ Aprovar tokens', callback_data: `approve_${txid}` }]],
      },
    };
    await bot.sendMessage(process.env.TELEGRAM_CHAT_ID, text, opts);
  }
  res.send(`<h2>✅ Pagamento registrado!</h2><p>Seu saldo será creditado após aprovação.</p><p><a href="/painel">Voltar</a></p>`);
});

if (bot) {
  bot.on('callback_query', async query => {
    const data = query.data || '';
    if (!data.startsWith('approve_')) return;
    const txid = data.slice('approve_'.length);
    const pend = loadPendentes();
    const idx = pend.findIndex(p => p.txid === txid);
    if (idx === -1) return bot.answerCallbackQuery(query.id, { text: 'TXID não encontrado.' });

    const { username, valor } = pend[idx];
    const u = getUser(username);
    updateUser(username, { tokens: (u.tokens || 0) + Number(valor) });
    pend.splice(idx, 1);
    savePendentes(pend);

    await bot.editMessageText(`✅ PIX ${txid} aprovado!\n+${valor} tokens para *${username}*`, {
      chat_id: query.message.chat.id,
      message_id: query.message.message_id,
      parse_mode: 'Markdown',
    });
    bot.answerCallbackQuery(query.id, { text: 'Tokens aprovados!' });
  });
}

/* =======================
   START
   ======================= */
app.listen(port, '0.0.0.0', () => {
  console.log(`✔ Servidor rodando em http://0.0.0.0:${port}`);
});
