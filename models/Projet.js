const mongoose = require("mongoose");

const ProjetSchema = mongoose.Schema({
    titre: {
        type: String,
        required: true,
    },
    adresse: {
        type: String,
        required: true,
    },

    description: {
        type: String,
        required: true,
    },
    images: {
        type: [String],
        required: true,
    },

    productionAnuelle: {
        type: String,
        required: true,
    },

    type: {
        type: String,
        required: true,
    },

    video: {
        type: String,
        required: true,
    },
    createdAt: {
        type: Date,
        default: Date.now,
    }

});

const Projet = mongoose.model("Projet", ProjetSchema);
module.exports = Projet;
