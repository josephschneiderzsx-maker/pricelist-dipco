const { body, validationResult } = require('express-validator');

const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  next();
};

const userValidationRules = () => {
  return [
    body('name').notEmpty().withMessage('Le nom est requis.'),
    body('username').notEmpty().withMessage('Le nom d\'utilisateur est requis.'),
    body('password').isLength({ min: 6 }).withMessage('Le mot de passe doit contenir au moins 6 caractères.'),
    body('role').isIn(['user', 'admin']).withMessage('Le rôle doit être "user" ou "admin".')
  ];
};

const articleValidationRules = () => {
  return [
    body('code').notEmpty().withMessage('Le code article est requis.'),
    body('description').notEmpty().withMessage('La description est requise.'),
    body('prix_vente').isFloat({ gt: 0 }).withMessage('Le prix de vente doit être un nombre positif.'),
    body('achat_minimum').isInt({ gt: 0 }).withMessage('L\'achat minimum doit être un entier positif.')
  ];
};

module.exports = {
  handleValidationErrors,
  userValidationRules,
  articleValidationRules,
};
