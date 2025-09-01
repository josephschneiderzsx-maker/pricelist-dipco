const jwt = require('jsonwebtoken');

// Middleware d'authentification
const authenticate = (req, res, next) => {
  const token = req.cookies.token || req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Non authentifié' });

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Session expirée ou token invalide' });
  }
};

// Middleware pour vérifier le rôle d'administrateur
const isAdmin = (req, res, next) => {
  if (req.user && req.user.role === 'admin') {
    next();
  } else {
    res.status(403).json({ error: 'Accès non autorisé. Rôle administrateur requis.' });
  }
};

module.exports = {
  authenticate,
  isAdmin
};
