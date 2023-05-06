const Puissance = require('../models/Puissance.js');


const addPuissance = async (req, res) => {
    let result = await Puissance.find();
    console.log(result);
    const { puissanceAllemande, puissanceChinoise } = req.body;
    const puissance = new Puissance({ puissanceAllemande, puissanceChinoise });

    try {
        if (result.length == 0) {
            console.log("tab3a kamla puissance", puissanceAllemande, puissanceChinoise)
            await puissance.save();
            return res.send(puissance);

        }
        return res.status(400).send("Puissance already exists, please refer to modify_puissance instead !");
    } catch (e) {
        res.status(400).send("mo7sen");
    }
};


const getPuissance = async (req, res) => {
    try {
        let result = await Puissance.find();
        if (!result) {
            return res.sendStatus(404);

        }
        res.status(200).json(result);
    } catch (error) {
        console.log(error);
        res.sendStatus(500);
    }
};


const modifierPuissance = async (req, res) => {
    console.log("req.body", req.body)
    const regex = /^\d+(\.\d+)?$/;
    const _id = req.params._id;
    const { puissanceAllemande, puissanceChinoise } = req.body;
    const modifiedPuissance = { puissanceAllemande, puissanceChinoise }

    if (!regex.test(puissanceAllemande)) {
        return res.sendStatus(402);
    }
    if (!regex.test(puissanceChinoise)) {
        return res.sendStatus(402);
    }

    try {
        const puissance = await Puissance.findOneAndUpdate({ _id }, modifiedPuissance, {
            new: true,
            runValidators: true,
        }).lean();
        if (!puissance) {
            return res.sendStatus(500);
        }
        res.send(puissance);
    } catch (error) {
        console.log(error);
        if (error instanceof mongoose.error.ValidationError) {
            return res.sendStatus(404);
        }
        return res.sendStatus(502);
    }
};


module.exports = {
    addPuissance,
    getPuissance,
    modifierPuissance,
};
