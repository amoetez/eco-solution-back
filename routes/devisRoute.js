const devisController = require('../controller/devisController.js');
const express = require('express');
const router = new express.Router();

router.post('/devis', (req, res) => {
    console.log("ena lina");
    devisController.addDevis(req, res)
});
module.exports = router;
