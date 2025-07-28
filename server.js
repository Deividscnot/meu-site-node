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
function loadPendentes() {
  if (!fsSync.existsSync(PENDENTES_FILE)) return [];
  return JSON.parse(fsSync.readFileSync(PENDENTES_FILE, 'utf8'));
}
function savePendentes(list) {
  fsSync.writeFileSync(PENDENTES_FILE, JSON.stringify(list, null, 2));
}

app.use('/static', express.static(path.join(__dirname, 'public')));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false }
}));
const upload = multer({ dest: path.join(__dirname, 'uploads') });

function loadUsers() {
  const file = path.join(__dirname, 'usuarios.json');
  if (!fsSync.existsSync(file)) return [];
  return JSON.parse(fsSync.readFileSync(file, 'utf8'));
}
function saveUsers(users) {
  fsSync.writeFileSync(
    path.join(__dirname, 'usuarios.json'),
    JSON.stringify(users, null, 2)
  );
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

const airbagsRouter = require('./data/airbags');
app.use('/airbags', airbagsRouter);

const bot = new TelegramBot(process.env.TELEGRAM_BOT_TOKEN, { polling: true });

app.get('/login', (req, res) => res.render('login', { error: null }));
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const u = getUser(username);
  if (u && bcrypt.compareSync(password, u.passwordHash)) {
    req.session.user = u;
    return res.redirect('/');
  }
  res.render('login', { error: 'Usuário ou senha inválidos' });
});
app.get('/register', (req, res) => res.render('register', { error: null }));
app.post('/register', (req, res) => {
  const { username, password } = req.body;
  const users = loadUsers();
  if (users.find(u => u.username === username)) {
    return res.send('Usuário já existe. <a href="/register">Voltar</a>');
  }
  const hash = bcrypt.hashSync(password, 10);
  users.push({ username, passwordHash: hash, tokens: 0 });
  saveUsers(users);
  res.redirect('/login');
});
app.get('/logout', (req, res) => req.session.destroy(() => res.redirect('/login')));

app.get('/', requireLogin, (req, res) => {
  const user = getUser(req.session.user.username);
  res.render('home', { user });
});
app.get('/alterar-km', requireLogin, (req, res) => {
  const user = getUser(req.session.user.username);
  res.render('painel', { user, currentKm: null, message: null });
});

const BROZ_FACTOR = 0.64;
function convertBrozToEepromBytes(km) {
  const valor = Math.round(km * BROZ_FACTOR);
  const buf = Buffer.alloc(2);
  buf.writeUInt16LE(valor, 0);
  return buf;
}

const mileageLocations = {
  titan160: [0x0098,0x009C,0x00A0,0x00A4,0x00A8,0x00AC,0x00B0,0x00B4,0x00B8,0x00BC,0x00C0,0x00C4,0x00C8,0x00CC,0x00D0,0x00D4,0x00D8,0x00DA,0x00DE,0x00E0,0x00E2],
  biz2018: [0x005C,0x0060,0x0064,0x0068,0x006C,0x0070,0x0074,0x0078,0x007C,0x0080,0x0084,0x0088,0x008C,0x0098],
  cb500x2023: [0x0100,0x0104,0x0108,0x010C,0x0110,0x0114,0x0118,0x011C,0x0120,0x0124,0x0128,0x012C,0x0130,0x0134,0x0138,0x013C],
  crosser150: [0x00A0,0x00A4,0x00A8,0x00B0,0x00B4,0x00B8,0x00C0,0x00C4,0x00C8,0x00D0,0x00D4,0x00D8],
  broz24C04: [0x01B2,0x01C2,0x01D2,0x01E2],
  cb300: [0x0080, 0x0090, 0x00C0, 0x00D0],
  cbtwister24c02: [0x0004],
  xt66024c02: [0x0028, 0x0030, 0x0040, 0x0050, 0x0060, 0x0070],
  xre190: [0x0098,0x009C,0x00A0,0x00A4,0x00A8,0x00AC,0x00B0,0x00B4,0x00B8,0x00BC,0x00C0,0x00C4,0x00C8,0x00CC,0x00D0,0x00D4,0x00D8,0x00DA,0x00DE,0x00E0,0x00E2]
};

function getModelConfig(model) {
  const cfg = {
    titan160: { template: 'titan160.bin', offsets: mileageLocations.titan160 },
    xre190: { template: 'xre190.bin', offsets: mileageLocations.xre190 },
    biz2018: { template: 'biz2018.bin', offsets: mileageLocations.biz2018 },
    cb500x2023: { template: 'cb500x2023.bin', offsets: mileageLocations.cb500x2023 },
    crosser150: { template: 'crosser150_base.bin', offsets: mileageLocations.crosser150 },
    broz24C04: { template: 'broz24C04.bin', offsets: mileageLocations.broz24C04 },
    cbtwister24c02: { template: 'cbtwister24c02.bin', offsets: mileageLocations.cbtwister24c02 },
    xt66024c02: { template: 'xt66024c02.bin', offsets: mileageLocations.xt66024c02 },
   cb300: { template: 'cb300_base.bin', offsets: mileageLocations.cb300 }
  }[model];
  if (!cfg) throw new Error(`Modelo inválido: ${model}`);
  return cfg;
}

function convertMileageToEepromBytes(km) {
  const valor = Math.floor(km * 0.031);
  const comp = 0xFFFF - valor;
  const buf = Buffer.alloc(4);
  buf.writeUInt16LE(valor, 0);
  buf.writeUInt16LE(comp, 2);
  return buf;
}

app.post('/ler-km', requireLogin, upload.single('binfile'), async (req, res) => {
  const user = getUser(req.session.user.username);
  try {
    if (!req.file) throw new Error('Nenhum arquivo enviado.');
    const buf = await fs.readFile(req.file.path);
    await fs.unlink(req.file.path);

    const model = req.body.model;
    const { offsets } = getModelConfig(model);
    let raw = null;

    if (model === 'cbtwister24c02') {
      raw = buf.readUInt16LE(offsets[0]);
    } else {
      for (const off of offsets) {
        if (model === 'broz24C04') {
          if (off + 2 > buf.length) continue;
          raw = buf.readUInt16LE(off);
          break;
        } else {
          if (off + 4 > buf.length) continue;
          const v = buf.readUInt16LE(off);
          const c = buf.readUInt16LE(off + 2);
          if (v + c === 0xFFFF) {
            raw = v;
            break;
          }
        }
      }
    }

    if (raw === null) throw new Error('Nenhum offset válido.');

    const km = model === 'broz24C04' ? Math.round(raw / BROZ_FACTOR)
             : model === 'cbtwister24c02' ? Math.round(raw / 3.4464)
             : model === 'xt66024c02' ? raw * 1000
             : Math.round(raw / 0.031);

    res.render('painel', { user, currentKm: km, message: null });
  } catch (err) {
    res.render('painel', { user, currentKm: null, message: `Erro: ${err.message}` });
  }
});

app.post('/alterar-e-baixar-template', requireLogin, async (req, res) => {
  try {
    const kmRaw = parseInt(req.body.new_mileage, 10);
    const model = req.body.model;
    if (isNaN(kmRaw) || kmRaw < 0) throw new Error('KM inválido');

    const user = getUser(req.session.user.username);
    if (user.tokens < FILE_TOKEN_COST) {
      return res.render('insufficient', { cost: FILE_TOKEN_COST });
    }
    updateUser(user.username, { tokens: user.tokens - FILE_TOKEN_COST });
    req.session.user.tokens = user.tokens - FILE_TOKEN_COST;

    const { template, offsets } = getModelConfig(model);
    const original = await fs.readFile(path.join(DATA_DIR, template));
    const buffer = Buffer.from(original);

    if (model === 'broz24C04') {
      const kmBytes = convertBrozToEepromBytes(kmRaw);
      kmBytes.copy(buffer, 0, 0, 2);
      offsets.forEach(off => {
        if (off + 2 <= buffer.length) {
          const brozBytes = Buffer.alloc(2);
          brozBytes.writeUInt16LE(Math.round(kmRaw * BROZ_FACTOR), 0);
          brozBytes.copy(buffer, off);
        }
      });
   } else if (model === 'cbtwister24c02') {
  const valor = Math.round(kmRaw * 3.4464);
  if (valor > 0xFFFF) throw new Error('KM muito alto para CB Twister (24C02). Máximo ≈ 99999 km');

  // Escreve os 2 bytes do valor
  buffer.writeUInt16LE(valor, 0x0004);

  // Escreve os próximos 2 bytes como 0xFFFF (possivelmente TRIP)
  buffer.writeUInt16LE(0xFFFF, 0x0006);

  // Zera (coloca FF) nos bytes de 0x0008 até 0x0033 (inclusive)
  for (let i = 0x0008; i <= 0x0033; i++) {
    buffer[i] = 0xFF;
  }
  }else if (model === 'xt66024c02') {
  if (kmRaw > 99999) throw new Error('Máximo permitido: 99.999 km para XT660');

  const kmByte = Math.floor(kmRaw / 1000); // 35000 → 35

  const padrao = Buffer.from([0x00, 0x00, kmByte, 0x00, 0x00, 0x00, 0x00, kmByte]);

  // Linha 0028: 2 blocos (a partir do byte 8)
  padrao.copy(buffer, 0x0028); // sobrescreve 8 bytes a partir do offset 0x0028

  // Linhas 0030 a 0070: preencher cada uma com 4 blocos (total 16 bytes por linha)
  const linhas = [0x0030, 0x0040, 0x0050, 0x0060, 0x0070];
  for (const offset of linhas) {
    for (let i = 0; i < 4; i++) {
      padrao.copy(buffer, offset + (i * 8));
    }
  }
}

    res.setHeader('Content-Disposition', `attachment; filename="${model}_${kmRaw}km.bin"`);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.send(buffer);
  } catch (err) {
    res.status(500).send(`Erro interno: ${err.message}`);
  }
});

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
      transactionId: txid
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

  const text = `*Novo PIX aguardando comprovante*\n` +
               `• Usuário: _${user.username}_\n` +
               `• Tokens: *+${valor}*\n` +
               `• TXID: \`${txid}\``;
  const opts = { parse_mode: 'Markdown', reply_markup: { inline_keyboard: [[{ text: '✅ Aprovar tokens', callback_data: `approve_${txid}` }]] } };
  await bot.sendMessage(process.env.TELEGRAM_CHAT_ID, text, opts);
  res.send(`<h2>✅ Pagamento registrado!</h2><p>Seu saldo será creditado após aprovação.</p><p><a href="/">Voltar</a></p>`);
});

bot.on('callback_query', async query => {
  const data = query.data;
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
    parse_mode: 'Markdown'
  });
  bot.answerCallbackQuery(query.id, { text: 'Tokens aprovados!' });
});

app.listen(port, '0.0.0.0', () => {
  console.log(`✔ Servidor rodando em http://0.0.0.0:${port}`);
});
