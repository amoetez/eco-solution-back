const express = require("express");
const router = new express.Router();
const indicateurController = require("../controller/indicateurController");
const auth = require("../middleware/authAdmin");


router.post("/indicateur/nouveauIndicateur",indicateurController.addIndicateur);

router.get("/indicateur", indicateurController.getIndicateur);

router.put("/indicateur/update/:_id",auth, indicateurController.modifierIndicateur);

module.exports = router;

