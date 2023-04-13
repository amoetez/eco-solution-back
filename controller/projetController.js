const { findById } = require("../models/Projet.js");
const Projet = require("../models/Projet.js");
const path = require("path");
const fs = require("fs");
const addProjet = async (req, res) => {
  const { description, titre, adresse, productionAnuelle, type, video } =
    JSON.parse(JSON.stringify(req.body));
  console.log("hahahaha", JSON.parse(JSON.stringify(req.body)));
  try {
    const images = [];
    for (const file of req.files.images) {
      if (!file.originalname.match(/\.(jpg|png|jpeg)$/)) {
        return res.status(400).send({ message: "please upload an image" });
      }
      images.push(path.basename(file.path));
    }
    // const video = path.basename(req.files.video[0].path);

    const projet = new Projet({
      description,
      titre,
      adresse,
      productionAnuelle,
      type,
      images,
      video,
    });
    console.log("heeeeeeeeey");
    await projet.save();
    res.send(projet);
  } catch (e) {
    console.log(e);
    res.status(400).send("problem when adding the projet");
  }
};

const getProjetById = async (req, res) => {
  try {
    let result = await Projet.findById(req.params._id);
    if (!result) {
      return res.sendStatus(404);
    }
    res.status(200).json(result);
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
};

const getProjets = async (req, res) => {
  try {
    let result = await Projet.find();
    if (!result) {
      res.sendStatus(404);
      return;
    }
    res.status(200).json(result);
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
};

const getLatestProjets = async (req, res) => {
  try {
    const result = await Projet.find().sort({ createdAt: -1 }).limit(1);
    res.send(result);
  } catch (error) {
    res.sendStatus(500);
  }
};

const modifierProjet = async (req, res) => {
  console.log(req.files);
  const _id = req.params._id;
  localData = {
    titre: req.body.titre,
    description: req.body.description,
    adresse: req.body.adresse,
    productionAnuelle: req.body.productionAnuelle,
    type: req.body.type,
  };
  if (req.files !== undefined && req.files.video !== undefined) {
    const video = path.basename(req.files.video[0]);
    localData["video"] = video;
  }

  if (req.files !== undefined && req.files.images !== undefined) {
    const images = req.files.images.map((file) => path.basename(file.path));
    localData["images"] = images;
  }

  if (!localData) {
    return res.sendStatus(404);
  }
  try {
    let projet = await Projet.findOneAndUpdate({ _id }, localData, {
      new: true,
      runValidators: true,
    }).lean();
    console.log(projet);

    if (!projet) {
      return res.sendStatus(404);
    }
    res.send(projet);
  } catch (error) {
    console.log(error);
    if (error instanceof mongoose.error.ValidationError) {
      return res.sendStatus(404);
    } else {
      return res.sendStatus(500);
    }
  }
};

const deleteById = async (req, res) => {
  try {
    const PATH_TO_UPLOADS = path.join(__dirname, "..", "uploads");

    const _id = req.params._id;
    const projet = await Projet.findById(_id);
    const imagesNames = projet.images;
    console.log(imagesNames);
    const videoPath = path.join(PATH_TO_UPLOADS, "videosProjet", projet.video);
    console.log(videoPath);

    const result = await Projet.deleteOne({ _id });
    console.log(result);
    if (result.deletedCount === 0) {
      return res.sendStatus(500);
    }
    if (imagesNames !== undefined) {
      imagesNames.forEach((imageName) => {
        const filePath = path.join(PATH_TO_UPLOADS, "imagesProjet", imageName);
        console.log(filePath);
        fs.unlink(filePath, (error) => {
          if (error) {
            console.log(error);
            return res.status(500).send(error);
          }
          console.log("kamelna");
          console.log(`${filePath} has been removed`);
        });
      });
    }
    if (projet.video !== undefined) {
      console.log("hani fil video");
      fs.unlink(videoPath, (error) => {
        console.log(videoPath);
        if (error) {
          console.log(error);
          return res.status(500).send(error);
        }
        console.log(`${videoPath} removed with success`);
      });
    }

    res.sendStatus(200);
  } catch (error) {
    res.sendStatus(500);
  }
};

module.exports = {
  addProjet,
  getProjetById,
  getProjets,
  getLatestProjets,
  modifierProjet,
  deleteById,
};
