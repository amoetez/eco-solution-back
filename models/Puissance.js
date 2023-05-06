const mongoose = require("mongoose");

const puissanceSchema = new mongoose.Schema({
    puissanceAllemande: {
        type: String,
        require: true
    },
    puissanceChinoise: {
        type: String,
        require: true
    }
});

const Puissance = mongoose.model("Puissance", puissanceSchema);

module.exports = Puissance;
