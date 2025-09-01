require('dotenv').config();
const express = require('express');
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

// Servir les fichiers statiques
app.use(express.static('public'));
app.use('/admin', express.static('admin'));


// Connexion DB
const pool = require('./src/config/database');

// Middleware pour logger les requêtes
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// Routes
const articleRoutes = require('./src/routes/articles.js');

app.use('/api/public', articleRoutes.publicRouter);
app.use('/api/admin', articleRoutes.adminRouter);


const { authenticate, isAdmin } = require('./src/middleware/auth.js');

const userRoutes = require('./src/routes/users.js');
app.use('/api/admin/users', userRoutes);

const authRoutes = require('./src/routes/auth.js');
app.use('/api/auth', authRoutes);

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