const { findById } = require('../models/Article.js');
const Article = require('../models/Article.js');
const path = require('path');
const fs = require('fs');

const addArticle = async (req, res) => {
    const { contenu, description, titre } = req.body;
    console.log('hedha itoken we ekhiran', req.cookies.token)
    // console.log('hedhi isession',req.session)
    // const token = req.session.token;
    // console.log('hedha itoken imta3 isession hedhi fil article', token);
    
    try {
        if(req.files == undefined || req.files.length === 0)
            {return res.status(400).send("problem when adding the article");}
        const images = [];
        for (const file of req.files) {
            if (!file.originalname.match(/\.(jpg|png|jpeg)$/)) {
                return res.status(400).send({ message: 'please upload an image' });
            }
            images.push(path.basename(file.path))
            console.log(images);
        };
        const article = new Article({ contenu, description, titre, images });
        await article.save();
        res.send(article);
    
    } catch (e) {
        res.status(400).send("problem when adding the article");
    }
};

const getArticleById = async (req, res) => {
    try {
        let article = await Article.findById(req.params._id);
        if (!article) {
            return res.sendStatus(404);
        }
        res.status(200).json(article);
    } catch (error) {
        console.log(error);
        res.sendStatus(500);
    }
};

const getArticles = async (req, res) => {
    try {
        const result = await Article.find();
        if (!result) {
            return res.sendStatus(404);
        }
        res.status(200).json(result);
    } catch (error) {
        console.log(error);
        res.sendStatus(500);
    }
};

const getLatestArticles = async (req, res) => {
    try {
       const result = await Article.find()
                                     .sort({createdAt: -1})
                                        .limit(1); 
        res.send(result);

    } catch (error) {
       res.sendStatus(500); 
    }
} 
const modifierArticle = async (req, res) => {
    const images = [];
    const modifiedArticle = {
        description: req.body.description,
        titre: req.body.titre,
        contenu: req.body.contenu,
    };

    if (req.files !== undefined) {
        req.files.forEach((file) => {
            if (!file.originalname.match(/\.(jpg|png|jpeg)$/)) {
                return res.status(400).send({ message: 'please upload an image' });
            }
            images.push(path.basename(file.path));
            modifiedArticle['images'] = images;
        });

    }
    if (modifiedArticle.titre==='' || modifiedArticle.description==='' || modifiedArticle.contenu==='') {
        return res.send('no value provided to make modifications');
    }
    console.log(modifiedArticle);
    try {
        let _id = req.params._id;
        let article = await Article.findOneAndUpdate({ _id }, modifiedArticle, {
            new: true,
            runValidators: true,
        }).lean();
        console.log(article);
        if (!article) {
            return res.sendStatus(405);
        }
        res.send(article);

    } catch (error) {
        console.log(error);
        if (error instanceof mongoose.error.ValidationError) {
            return res.status(400).send({ message: 'validation error' });
        }
        return res.status(500).send();
    }
}
const deleteById = async (req, res) => {
    try {
        const PATH_TO_THE_IMAGES_ARTICLE_DIRECTORY = path.join(__dirname,'..','uploads','imagesArticle');
        const _id = req.params._id;
        const article = await Article.findById(_id);
        const imagesNames = article.images;
        const result = await Article.deleteOne({ _id });
        if (result.deletedCount === 0) {
            return res.sendStatus(500);
        }
        if (imagesNames !== undefined) {
            imagesNames.forEach((imageName) => {
                const filePath = path.join(PATH_TO_THE_IMAGES_ARTICLE_DIRECTORY,imageName);
                fs.unlink(filePath,(error)=>{
                    if (error) {
                        console.log(error);
                        return;
                    }
                   console.log(`${filePath} has been removed`);
                })
            })

        }
        res.sendStatus(200);
    } catch (error) {
        res.sendStatus(500);
    }
};
module.exports = {
    addArticle,
    getArticleById,
    getArticles,
    getLatestArticles,
    modifierArticle,
    deleteById
};
