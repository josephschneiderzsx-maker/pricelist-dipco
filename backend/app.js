require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors({
  origin: ['https://dipco.itxpress.net', 'https://www.dipco.itxpress.net'],
  credentials: true
}));
app.use(express.json());
app.use(cookieParser());
app.set('trust proxy', 1);

// Rate limiter pour le login
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { message: 'Trop de tentatives, veuillez réessayer plus tard' }
});

// Connexion DB
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Middleware pour logger les requêtes
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// Routes publiques
app.get('/api/public/articles', async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 100;
  const searchTerm = req.query.search;
  const offset = (page - 1) * limit;

  try {
    let query = 'SELECT * FROM articles';
    const queryParams = [];

    if (searchTerm) {
      query += ' WHERE code LIKE ? OR description LIKE ? OR demar LIKE ? OR type LIKE ?';
      queryParams.push(`%${searchTerm}%`, `%${searchTerm}%`, `%${searchTerm}%`, `%${searchTerm}%`);
    }

    query += ' ORDER BY id ASC LIMIT ? OFFSET ?';
    queryParams.push(limit, offset);

    const [rows] = await pool.query(query, queryParams);

    // Convertir les prix en nombres
    const articles = rows.map(row => ({
      ...row,
      prix_vente: parseFloat(row.prix_vente),
      achat_minimum: parseFloat(row.achat_minimum)
    }));

    res.json(articles);
  } catch (err) {
    console.error('Erreur récupération articles:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Authentification
app.post('/api/auth/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body;

  try {
    const [users] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    if (users.length === 0) return res.status(401).json({ error: 'Identifiants invalides' });

    const user = users[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Identifiants invalides' });

    // JWT
    const token = jwt.sign(
      { id: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN }
    );

    res.cookie('token', token, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: 15 * 60 * 1000 // 15 minutes
    }).json({ token, user: { id: user.id, name: user.name, username: user.username, role: user.role } });
  } catch (err) {
    console.error('Erreur login:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Middleware d'authentification
const authenticate = (req, res, next) => {
  const token = req.cookies.token || req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Non authentifié' });

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (err) {
    res.status(401).json({ error: 'Session expirée' });
  }
};

// Middleware admin
const isAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Accès non autorisé' });
  }
  next();
};

// CRUD Articles
app.get('/api/admin/articles', authenticate, isAdmin, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM articles');
    res.json(rows);
  } catch (err) {
    console.error('Erreur admin/articles:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.post('/api/admin/articles', authenticate, isAdmin, async (req, res) => {
  const { code, description, demar, prix_vente, achat_minimum, unite, type } = req.body;

  try {
    const [result] = await pool.execute(
      'INSERT INTO articles (code, description, demar, prix_vente, achat_minimum, unite, type) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [code, description, demar, prix_vente, achat_minimum, unite, type]
    );

    res.status(201).json({ id: result.insertId });
  } catch (err) {
    console.error('Erreur création article:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.put('/api/admin/articles/:id', authenticate, isAdmin, async (req, res) => {
  const id = req.params.id;
  const { code, description, demar, prix_vente, achat_minimum, unite, type } = req.body;

  try {
    await pool.execute(
      'UPDATE articles SET code=?, description=?, demar=?, prix_vente=?, achat_minimum=?, unite=?, type=? WHERE id=?',
      [code, description, demar, prix_vente, achat_minimum, unite, type, id]
    );

    res.json({ message: 'Article mis à jour' });
  } catch (err) {
    console.error('Erreur mise à jour article:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.delete('/api/admin/articles/:id', authenticate, isAdmin, async (req, res) => {
  const id = req.params.id;

  try {
    await pool.execute('DELETE FROM articles WHERE id=?', [id]);
    res.json({ message: 'Article supprimé' });
  } catch (err) {
    console.error('Erreur suppression article:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ================= GESTION DES UTILISATEURS =================

// GET - Récupérer tous les utilisateurs
app.get('/api/admin/users', authenticate, isAdmin, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT id, name, username, role, created_at FROM users');
    res.json(rows);
  } catch (err) {
    console.error('Erreur récupération utilisateurs:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// GET - Récupérer un utilisateur spécifique
app.get('/api/admin/users/:id', authenticate, isAdmin, async (req, res) => {
  const { id } = req.params;
  
  try {
    const [rows] = await pool.query('SELECT id, name, username, role, created_at FROM users WHERE id = ?', [id]);
    
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Utilisateur non trouvé' });
    }
    
    res.json(rows[0]);
  } catch (err) {
    console.error('Erreur récupération utilisateur:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// POST - Créer un nouvel utilisateur
app.post('/api/admin/users', authenticate, isAdmin, async (req, res) => {
  const { name, username, password, role } = req.body;

  // Validation des données
  if (!name || !username || !password) {
    return res.status(400).json({ error: 'Nom, username et mot de passe sont requis' });
  }

  try {
    // Vérifier si l'utilisateur existe déjà
    const [existingUsers] = await pool.query('SELECT id FROM users WHERE username = ?', [username]);
    if (existingUsers.length > 0) {
      return res.status(409).json({ error: 'Cet username est déjà utilisé' });
    }

    // Hacher le mot de passe
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Insérer le nouvel utilisateur
    const [result] = await pool.execute(
      'INSERT INTO users (name, username, password, role) VALUES (?, ?, ?, ?)',
      [name, username, hashedPassword, role || 'user']
    );

    res.status(201).json({ 
      id: result.insertId, 
      message: 'Utilisateur créé avec succès' 
    });
  } catch (err) {
    console.error('Erreur création utilisateur:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// PUT - Mettre à jour un utilisateur
app.put('/api/admin/users/:id', authenticate, isAdmin, async (req, res) => {
  const { id } = req.params;
  const { name, username, password, role } = req.body;

  try {
    // Vérifier si l'utilisateur existe
    const [users] = await pool.query('SELECT id FROM users WHERE id = ?', [id]);
    if (users.length === 0) {
      return res.status(404).json({ error: 'Utilisateur non trouvé' });
    }

    // Vérifier si le nouvel username est déjà utilisé par un autre utilisateur
    const [existingUsers] = await pool.query('SELECT id FROM users WHERE username = ? AND id != ?', [username, id]);
    if (existingUsers.length > 0) {
      return res.status(409).json({ error: 'Cet username est déjà utilisé' });
    }

    let query = 'UPDATE users SET name = ?, username = ?, role = ?';
    let params = [name, username, role];

    // Si un nouveau mot de passe est fourni, le hacher et l'ajouter à la requête
    if (password) {
      const saltRounds = 10;
      const hashedPassword = await bcrypt.hash(password, saltRounds);
      query += ', password = ?';
      params.push(hashedPassword);
    }

    query += ' WHERE id = ?';
    params.push(id);

    await pool.execute(query, params);

    res.json({ message: 'Utilisateur mis à jour avec succès' });
  } catch (err) {
    console.error('Erreur mise à jour utilisateur:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// DELETE - Supprimer un utilisateur
app.delete('/api/admin/users/:id', authenticate, isAdmin, async (req, res) => {
  const { id } = req.params;

  try {
    // Vérifier si l'utilisateur existe
    const [users] = await pool.query('SELECT id FROM users WHERE id = ?', [id]);
    if (users.length === 0) {
      return res.status(404).json({ error: 'Utilisateur non trouvé' });
    }

    // Empêcher la suppression de son propre compte
    if (parseInt(id) === req.user.id) {
      return res.status(400).json({ error: 'Vous ne pouvez pas supprimer votre propre compte' });
    }

    await pool.execute('DELETE FROM users WHERE id = ?', [id]);

    res.json({ message: 'Utilisateur supprimé avec succès' });
  } catch (err) {
    console.error('Erreur suppression utilisateur:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Route pour vérifier l'authentification
app.get('/api/auth/verify', authenticate, (req, res) => {
  res.json({ authenticated: true, user: req.user });
});

// Route de déconnexion
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token').json({ message: 'Déconnexion réussie' });
});

// Démarrer le serveur
app.listen(PORT, () => {
  console.log(`Serveur démarré sur le port ${PORT}`);
});

// Gestion des erreurs non catchées
process.on('uncaughtException', err => {
  console.error('Exception non gérée:', err);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Rejet non géré:', reason);
});