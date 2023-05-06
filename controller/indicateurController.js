const Indicateur = require('../models/Indicateur.js');

const addIndicateur = async (req, res) => {
    let result = await Indicateur.find();
    console.log(result);
    const indicateur = new Indicateur(req.body);

    try {
        if (result.length == 0) {
            console.log("tab3a kamla indicateurs", req.body)
            await indicateur.save();
            return res.send(indicateur);

        }
        return res.status(400).send("Indicateur already exists, please refer to modify_indicateur instead !");
    } catch (e) {
        res.status(400).send("mo7sen");
    }
};


const getIndicateur = async (req, res) => {
    try {
        let result = await Indicateur.find();
        if (!result) {
            return res.sendStatus(404);
        }
        res.status(200).json(result);
    } catch (error) {
        console.log(error);
        res.sendStatus(500);
    }
};


const modifierIndicateur = async (req, res) => {
    console.log("req.body", req.body)
    const regexFloat = /^\d+(\.\d+)?$/;
    const regexInt = /^\d+$/;
    const _id = req.params._id;
    const modifiedIndicateur = { ...req.body };
    console.log('hedha ilmodifiedIndicateur', modifiedIndicateur);

    if (!regexFloat.test(modifiedIndicateur.indicateurCarbone)) {
        return res.sendStatus(402);
    }
    if (!regexFloat.test(modifiedIndicateur.indicateurPuissance)) {
        return res.sendStatus(402);
    }
    if (!regexInt.test(modifiedIndicateur.indicateurNombreDeProjet)) {
        return res.sendStatus(402);
    }

    try {
        const indicateur = await Indicateur.findOneAndUpdate({ _id }, modifiedIndicateur, {
            new: true,
            runValidators: true,
        }).lean();
        if (!indicateur) {
            return res.sendStatus(500);
        }
        res.send(indicateur);
    } catch (error) {
        console.log(error);
        if (error instanceof mongoose.error.ValidationError) {
            return res.sendStatus(404);
        }
        return res.sendStatus(502);
    }
};


module.exports = {
    addIndicateur,
    getIndicateur,
    modifierIndicateur
};

