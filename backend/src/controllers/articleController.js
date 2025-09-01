const pool = require('../config/database');

// Contrôleur pour les routes publiques
const getPublicArticles = async (req, res) => {
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
};

// Contrôleurs pour les routes admin
const getAdminArticles = async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM articles');
    res.json(rows);
  } catch (err) {
    console.error('Erreur admin/articles:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
};

const createArticle = async (req, res) => {
  const { code, description, demar, prix_vente, achat_minimum, unite, type } = req.body;

  try {
    const [result] = await pool.execute(
      'INSERT INTO articles (code, description, demar, prix_vente, achat_minimum, unite, type) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [code, description, demar, prix_vente, achat_minimum, unite, type]
    );

    res.status(201).json({ id: result.insertId, message: 'Article créé avec succès' });
  } catch (err) {
    console.error('Erreur création article:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
};

const updateArticle = async (req, res) => {
  const { id } = req.params;
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
};

const deleteArticle = async (req, res) => {
  const { id } = req.params;

  try {
    await pool.execute('DELETE FROM articles WHERE id=?', [id]);
    res.json({ message: 'Article supprimé' });
  } catch (err) {
    console.error('Erreur suppression article:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
};

module.exports = {
  getPublicArticles,
  getAdminArticles,
  createArticle,
  updateArticle,
  deleteArticle,
};
