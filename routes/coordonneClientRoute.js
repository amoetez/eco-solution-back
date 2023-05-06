const express = require("express");
const router = new express.Router();
const coordonneClientController = require("../controller/coordonneClientController");


router.post("/coordonneClient/nouveauCoordonneClient", async (req, res) => {
    coordonneClientController.addCoordonneClient(req, res);
});


router.get("/coordonneClient", async (req, res) => {
    coordonneClientController.getCoordonneClient(req, res);
});





module.exports = router;
