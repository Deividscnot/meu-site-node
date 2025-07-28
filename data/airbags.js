const express = require('express');
const fs = require('fs').promises;
const fsSync = require('fs');
const path = require('path');
const router = express.Router();

const FILE_TOKEN_COST = 80;
const DATA_DIR = path.join(__dirname, 'airbags');

// 🔐 Middleware para exigir login
function requireLogin(req, res, next) {
  if (req.session?.user) return next();
  res.redirect('/login');
}

// Helpers de usuário
function loadUsers() {
  const file = path.join(__dirname, '..', 'usuarios.json');
  if (!fsSync.existsSync(file)) return [];
  return JSON.parse(fsSync.readFileSync(file, 'utf8'));
}
function getUser(username) {
  return loadUsers().find(u => u.username === username);
}
function updateUser(username, updates) {
  const users = loadUsers();
  const idx = users.findIndex(u => u.username === username);
  if (idx !== -1) {
    users[idx] = { ...users[idx], ...updates };
    fsSync.writeFileSync(
      path.join(__dirname, '..', 'usuarios.json'),
      JSON.stringify(users, null, 2)
    );
  }
}

// 🔍 Busca por número de airbag
router.get('/buscar', requireLogin, async (req, res) => {
  const termo = (req.query.q || '').toLowerCase();
  const user = getUser(req.session?.user?.username);

  if (!termo) {
    return res.render('airbags/busca', {
      termo: '',
      resultados: [],
      user
    });
  }

  async function buscarArquivos(dir, base = '') {
    const encontrados = [];
    const entries = await fs.readdir(dir, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      const relative = path.join(base, entry.name);

      if (entry.isDirectory()) {
        const internos = await buscarArquivos(fullPath, relative);
        encontrados.push(...internos);
      } else if ((entry.name.endsWith('.clear') || entry.name.endsWith('.info')) && entry.name.toLowerCase().includes(termo)) {
        encontrados.push(relative);
      }
    }

    return encontrados;
  }

  try {
    const resultados = await buscarArquivos(DATA_DIR);
    res.render('airbags/busca', {
      termo,
      resultados,
      user
    });
  } catch (err) {
    res.status(500).send('Erro ao buscar: ' + err.message);
  }
});

// 📥 Rota protegida de download com desconto de tokens
router.get('/download/*', requireLogin, async (req, res) => {
  const arquivo = req.params[0];
  const fullPath = path.join(DATA_DIR, arquivo);

  const user = getUser(req.session?.user?.username);
  if (!user) return res.status(403).send('Usuário inválido');

  if (!fsSync.existsSync(fullPath)) return res.status(404).send('Arquivo não encontrado');

  if (user.tokens < FILE_TOKEN_COST) {
    return res.send('Saldo insuficiente. <a href="/">Voltar</a>');
  }

  updateUser(user.username, { tokens: user.tokens - FILE_TOKEN_COST });
  req.session.user.tokens = user.tokens - FILE_TOKEN_COST;

  res.download(fullPath);
});

module.exports = router;
