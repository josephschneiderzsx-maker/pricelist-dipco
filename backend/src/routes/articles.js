const express = require('express');
const articleController = require('../controllers/articleController.js');
const { authenticate, isAdmin } = require('../middleware/auth.js');

const publicRouter = express.Router();
const adminRouter = express.Router();

// Route publique
publicRouter.get('/articles', articleController.getPublicArticles);

const { articleValidationRules, handleValidationErrors } = require('../middleware/validators.js');

// Routes admin (protégées)
adminRouter.get('/articles', authenticate, isAdmin, articleController.getAdminArticles);
adminRouter.post('/articles', authenticate, isAdmin, articleValidationRules(), handleValidationErrors, articleController.createArticle);
adminRouter.put('/articles/:id', authenticate, isAdmin, articleValidationRules(), handleValidationErrors, articleController.updateArticle);
adminRouter.delete('/articles/:id', authenticate, isAdmin, articleController.deleteArticle);

module.exports = {
  publicRouter,
  adminRouter
};
