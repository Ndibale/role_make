const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const LoginLimiter = require('../midleware/LoginLimiter');


router.route('/login')
    .post(LoginLimiter, authController.login)



router.route('/refresh')
    .get(authController.refresh)



router.route('/logout')
    .post(authController.logout)


module.exports = router