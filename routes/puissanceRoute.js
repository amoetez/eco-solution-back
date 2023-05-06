const express = require("express");
const router = new express.Router();
const puissanceController = require("../controller/puissanceController");
const auth = require("../middleware/authAdmin");


router.post("/puissance/nouveauPuissance",puissanceController.addPuissance);


router.get("/puissance", puissanceController.getPuissance);

router.put("/puissance/update/:_id", auth, puissanceController.modifierPuissance);

module.exports = router;
