const express = require('express');

const router = new express.Router();
const articleController = require('../controller/articleController');
const auth = require('../middleware/authAdmin');
const multer = require('multer');

const storage = multer.diskStorage({
    destination: function(req, file, cb) {
        cb(null, 'uploads/imagesArticle');
    },
    filename: function(req, file, cb) {
        cb(null, new Date().toISOString().replace(/:/g, '-') + file.originalname)
    }
});

const upload = multer({
    limits: {
        fileSize: 5000000
    },
    storage: storage
});

router.post("/article/ajouter_article", auth, upload.array('images', 10), articleController.addArticle);

router.get("/article/:_id", async (req, res) => {
    articleController.getArticleById(req, res);
});

router.get("/articles", async (req, res) => {
    articleController.getArticles(req, res);
});

router.get("/latestArticles", async (req, res) =>{
    articleController.getLatestArticles(req, res);
})
router.put("/article/update/:_id", auth, upload.array('images', 10), async (req, res) => {
    articleController.modifierArticle(req, res);
});


router.delete("/article/:_id", auth, async (req, res) => {
    articleController.deleteById(req, res);
});

module.exports = router;
