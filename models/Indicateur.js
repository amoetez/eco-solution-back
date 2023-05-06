const mongoose = require("mongoose");

const indicateurSchema = new mongoose.Schema({
    indicateurCarbone: {
        type: String,
        require: true
    },
    indicateurPuissance: {
        type: String,
        require: true
    },
    indicateurNombreDeProjet:{
        type: String,
        require: true
    }
});

const Indicateur = mongoose.model("Indicateur", indicateurSchema);

module.exports = Indicateur;

