const mongoose = require("mongoose")

const devisSchema = new mongoose.Schema({
    firstName: {
        type: String,
        require: true
    },
    lastName: {
        type: String,
        require: true
    },
    phoneNumber: {
        type: String,
        require: true
    },
    email: {
        type: String,
        require: true
    },
    adress: {
        type: String,
        require: true
    },
    job: {
        type: String,
        require: true
    },
    age: {
        type: String,
        require: true
    },
    type: {
        type: String,
        require: true

    },
    technology: {
        type: String,
        require: true

    },
    place: {
        type: String,
        require: true

    },
    longueur: {
        type: String,
        require: true

    },
    largeur: {
        type: String,
        require: true

    },
    orientation: {
        type: String,
        require: true

    },
    puissance: {
        type: Number,
        require: true
    }

});

const Devis = mongoose.model("Devis", devisSchema);

module.exports = Devis;


