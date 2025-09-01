const pool = require('../config/database');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// Contrôleur de connexion
const login = async (req, res) => {
  const { username, password } = req.body;

  try {
    const [users] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    if (users.length === 0) {
      return res.status(401).json({ error: 'Identifiants invalides' });
    }

    const user = users[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      return res.status(401).json({ error: 'Identifiants invalides' });
    }

    const token = jwt.sign(
      { id: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '1h' }
    );

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production', // Mettre à true en production
      sameSite: 'strict',
      maxAge: 60 * 60 * 1000 // 1 heure
    }).json({
      token, // Envoyer le token dans le corps est redondant si on utilise les cookies, mais le frontend actuel en dépend
      user: { id: user.id, name: user.name, username: user.username, role: user.role }
    });
  } catch (err) {
    console.error('Erreur login:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
};

// Vérifier le statut de l'authentification
const verifyAuth = (req, res) => {
  // Le middleware `authenticate` a déjà fait le travail.
  // S'il est passé, l'utilisateur est authentifié.
  res.json({ authenticated: true, user: req.user });
};

// Déconnexion
const logout = (req, res) => {
  res.clearCookie('token').json({ message: 'Déconnexion réussie' });
};

module.exports = {
  login,
  verifyAuth,
  logout
};
