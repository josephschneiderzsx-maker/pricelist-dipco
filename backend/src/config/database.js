const mysql = require('mysql2/promise');

// Pool de connexions MySQL
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  // Ajout d'une option pour gérer les erreurs de connexion
  namedPlaceholders: true,
  // charset: 'utf8mb4' // Optionnel, mais recommandé
});

// Test de la connexion
pool.getConnection()
  .then(connection => {
    console.log('Connexion à la base de données MySQL réussie.');
    connection.release();
  })
  .catch(err => {
    console.error('Erreur de connexion à la base de données:', err);
  });

module.exports = pool;
