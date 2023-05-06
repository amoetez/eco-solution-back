const express = require('express');

const router = new express.Router();
const projetController = require("../controller/projetController");
const multer = require('multer');
const auth = require('../middleware/authAdmin');

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        if (file.mimetype === 'image/jpg' || file.mimetype === 'image/jpeg' || file.mimetype === 'image/png') {
            cb(null, './uploads/imagesProjet');
        }
        else if (file.mimetype === 'video/mp4') {
            cb(null, './uploads/videosProjet');
        }
    },
    filename: (req, file, cb) => {
        cb(null, new Date().toISOString().replace(/:/g, '-') + file.originalname)
    }
});
const upload = multer({
    storage: storage
});
router.post('/projet/ajouter_projet', auth, upload.fields([{ name: 'images', maxCount: 10 }, { name: 'video', maxCount: 1 }]), async (req, res) => {
    projetController.addProjet(req, res);
})

router.get(
    '/projet/:_id',
    async (req, res) => {
        projetController.getProjetById(req, res);
    }
)

router.get(
    '/projets',
    async (req, res) => {
        projetController.getProjets(req, res);
    }
)
router.get("/latestProjets", async (req, res) =>{
    projetController.getLatestProjets(req, res);
})

router.put("/projet/update/:_id", auth, upload.fields([{ name: 'images', maxCount: 10 }, { name: 'video', maxCount: 1 }]), async (req, res) => {
    projetController.modifierProjet(req, res);
});

router.delete("/projet/:_id", auth, async (req, res) => {
    try {
        console.log("are you here ?")
        let result = await projetController.deleteById(req, res);

    } catch (error) {
        res.status(404).send("Base to teslek");
    }
});
module.exports = router
