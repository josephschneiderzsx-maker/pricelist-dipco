const express = require('express');
const rateLimit = require('express-rate-limit');
const authController = require('../controllers/authController.js');
const { authenticate } = require('../middleware/auth.js');

const router = express.Router();

// Limiteur de tentatives de connexion
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limite chaque IP à 5 requêtes de connexion par fenêtre
  message: { message: 'Trop de tentatives de connexion, veuillez réessayer plus tard.' },
  standardHeaders: true, // Retourne les informations de rate limit dans les en-têtes `RateLimit-*`
  legacyHeaders: false, // Désactive les en-têtes `X-RateLimit-*`
});

// Routes d'authentification
router.post('/login', loginLimiter, authController.login);
router.post('/logout', authController.logout);
router.get('/verify', authenticate, authController.verifyAuth);

module.exports = router;
