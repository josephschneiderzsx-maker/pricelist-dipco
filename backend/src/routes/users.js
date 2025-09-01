const express = require('express');
const userController = require('../controllers/userController.js');
const { authenticate, isAdmin } = require('../middleware/auth.js');

const router = express.Router();

// Toutes les routes ici sont préfixées par /api/admin/users et sont protégées
router.use(authenticate, isAdmin);

router.get('/', userController.getAllUsers);
const { userValidationRules, handleValidationErrors } = require('../middleware/validators.js');

router.post('/', userValidationRules(), handleValidationErrors, userController.createUser);
router.get('/:id', userController.getUserById);
router.put('/:id', userValidationRules(), handleValidationErrors, userController.updateUser);
router.delete('/:id', userController.deleteUser);

module.exports = router;
