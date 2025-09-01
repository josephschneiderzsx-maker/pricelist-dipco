const pool = require('../config/database');
const bcrypt = require('bcrypt');

// GET - Récupérer tous les utilisateurs
const getAllUsers = async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT id, name, username, role, created_at FROM users');
    res.json(rows);
  } catch (err) {
    console.error('Erreur récupération utilisateurs:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
};

// GET - Récupérer un utilisateur spécifique
const getUserById = async (req, res) => {
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
};

// POST - Créer un nouvel utilisateur
const createUser = async (req, res) => {
  const { name, username, password, role } = req.body;

  if (!name || !username || !password) {
    return res.status(400).json({ error: 'Nom, username et mot de passe sont requis' });
  }

  try {
    const [existingUsers] = await pool.query('SELECT id FROM users WHERE username = ?', [username]);
    if (existingUsers.length > 0) {
      return res.status(409).json({ error: 'Cet username est déjà utilisé' });
    }

    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

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
};

// PUT - Mettre à jour un utilisateur
const updateUser = async (req, res) => {
  const { id } = req.params;
  const { name, username, password, role } = req.body;

  try {
    const [users] = await pool.query('SELECT id FROM users WHERE id = ?', [id]);
    if (users.length === 0) {
      return res.status(404).json({ error: 'Utilisateur non trouvé' });
    }

    const [existingUsers] = await pool.query('SELECT id FROM users WHERE username = ? AND id != ?', [username, id]);
    if (existingUsers.length > 0) {
      return res.status(409).json({ error: 'Cet username est déjà utilisé' });
    }

    let query = 'UPDATE users SET name = ?, username = ?, role = ?';
    let params = [name, username, role];

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
};

// DELETE - Supprimer un utilisateur
const deleteUser = async (req, res) => {
  const { id } = req.params;

  try {
    const [users] = await pool.query('SELECT id FROM users WHERE id = ?', [id]);
    if (users.length === 0) {
      return res.status(404).json({ error: 'Utilisateur non trouvé' });
    }

    if (parseInt(id) === req.user.id) {
      return res.status(400).json({ error: 'Vous ne pouvez pas supprimer votre propre compte' });
    }

    await pool.execute('DELETE FROM users WHERE id = ?', [id]);

    res.json({ message: 'Utilisateur supprimé avec succès' });
  } catch (err) {
    console.error('Erreur suppression utilisateur:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
};

module.exports = {
  getAllUsers,
  getUserById,
  createUser,
  updateUser,
  deleteUser
};
