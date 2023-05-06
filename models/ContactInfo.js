const mongoose = require("mongoose");

const ContactInfoSchema = mongoose.Schema({
  siegeSocial: {
    type: String,
    required: true,
  },
  numeroTelephone: {
    type: String,
    required: true,
  },

  email: {
    type: String,
    required: true,
  },

  localisation: {
    type: String,
    required: true,
  },

  lienFacebook: {
    type: String,
    required: true,
  },
  
});

const ContactInfo = mongoose.model("ContactInfo", ContactInfoSchema);
module.exports = ContactInfo;
