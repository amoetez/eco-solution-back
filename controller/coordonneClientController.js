const CoordonneClient = require('../models/CoordonneClient.js');


const addCoordonneClient = async (req, res) => {
    
    
    const { nom,prenom, numeroTelephone,age,email,fonction,localisation } = req.body;
    const coordonneClient = new CoordonneClient({ nom,prenom, numeroTelephone,age,email,fonction,localisation });
    
    try {
        await coordonneClient.save();
        return res.send(coordonneClient);
    } catch (e) {
        res.status(400).send("mo7sen");
    }
};

const getCoordonneClient = async (req, res) => {
    try {
        let result = await CoordonneClient.find();
        if (!result) {
            return res.sendStatus(404);

        }
        res.status(200).json(result);
    } catch (error) {
        console.log(error);
        res.sendStatus(500);
    }
};

module.exports = {
    addCoordonneClient,
    getCoordonneClient,
    
};
