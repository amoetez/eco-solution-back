const Devis = require('../models/Devis.js');
const addDevis = async (req, res) => {
    console.log(req.body);
    const devis = new Devis(req.body);

    try {
        console.log("tab3a kamla devis", devis)
        await devis.save();
        res.send("devis sent successfully");

    } catch (e) {
        res.status(400).send("mo7sen");
    }
};
module.exports = {
    addDevis
};

