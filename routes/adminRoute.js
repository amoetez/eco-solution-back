const adminController = require('../controller/adminController');
const auth = require('../middleware/authAdmin');
const express = require('express');
const router = new express.Router();

router.post('/admin', async (req, res) => {
    adminController.addAdmin(req, res);
});

router.post('/admin/login', async (req, res) => {
    adminController.loginAdmin(req, res);
});

router.post('/admin/logout', auth, async (req, res) => {
    console.log('ena fil admin logout');
    adminController.logoutCurrentSessionAdmin(req, res);
});

router.post('/admin/logoutAll', auth, async (req, res) => {
    adminController.logoutAllSessionAdmin(req, res);
});

module.exports = router;
