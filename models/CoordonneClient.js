const mongoose = require("mongoose");

const CoordonneClientSchema = mongoose.Schema({
  nom: {
    type: String,
    required: true,
  },
  prenom: {
    type: String,
    required: true,
  },

  numeroTelephone: {
    type: String,
    required: true,
  },

  age: {
    type: String,
    required: true,
  },

  email: {
    type: String,
    required: true,
  },
  fonction: {
    type: String,
    required: true,
  },
  localisation: {
    type: String,
    required: true,
  },
  
});

const CoordonneClient = mongoose.model("CoordonneClient", CoordonneClientSchema);
module.exports = CoordonneClient;
