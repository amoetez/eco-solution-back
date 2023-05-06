const express = require("express");
const router = new express.Router();
const contactInfoController = require("../controller/contactInfoController");
const auth = require('../middleware/authAdmin');


router.post("/contactInfo/nouveauContact", async (req, res) => {
    contactInfoController.addContactInfo(req, res);
});



router.get("/contactInfo", async (req, res) => {
    contactInfoController.getContactInfo(req, res);
});


router.put("/contactInfo/update/:_id", auth, async (req, res) => {
    contactInfoController.modifierContactInfo(req, res);
});


module.exports = router;
