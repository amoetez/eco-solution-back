const express = require("express");
const router = new express.Router();
const serviceController = require("../controller/serviceController");
const multer = require('multer');
const auth = require("../middleware/authAdmin");

const storage = multer.diskStorage({
    destination: function(req, file, cb) {
        cb(null, 'uploads/imageService')
    },
    filename: function(req, file, cb) {
        cb(null, new Date().toISOString().replace(/:/g, '-') + file.originalname)
    }
});

const upload = multer({
    limits: {
        fileSize: 5000000
    },
    fileFilter(req, file, cb) {
        if (!file.originalname.match(/\.(jpg|png|jpeg)$/)) {
            return cb(new Error('please upload an image'));
        }
        cb(undefined, true);
    },
    storage: storage
})

router.post("/service/ajouter_service", auth, upload.single('image'), async (req, res) => {
    serviceController.addService(req, res);
});

router.get("/service/:_id", async (req, res) => {
    serviceController.getServiceById(req, res);
});

router.get("/services", async (req, res) => {
    serviceController.getServices(req, res);
});

router.put("/service/update/:_id", auth, upload.single('image'), async (req, res) => {
    serviceController.modifierService(req, res);
});

router.delete("/service/:_id", auth, async (req, res) => {
    serviceController.deleteById(req, res);
});

module.exports = router;
