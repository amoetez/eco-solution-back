const { findById } = require('../models/ContactInfo.js');
const ContactInfo = require('../models/ContactInfo.js');


const addContactInfo = async (req, res) => {
    let result = await ContactInfo.find();
    console.log(result);
    const { siegeSocial, numeroTelephone,email,localisation,lienFacebook } = req.body;
    const contactInfo = new ContactInfo({ siegeSocial, numeroTelephone,email,localisation,lienFacebook });
    
    try {
        if(result.length==0){
        console.log(siegeSocial, numeroTelephone,email,localisation,lienFacebook)
        await contactInfo.save();
        return res.send(contactInfo);
        
        }
        return res.status(400).send("Info contact already exists, please refer to modify_info_contact instead !");
    } catch (e) {
        res.status(400).send("mo7sen");
    }
};

const getContactInfo = async (req, res) => {
    try {
        let result = await ContactInfo.find();
        if (!result) {
            return res.sendStatus(404);

        }
        res.status(200).json(result);
    } catch (error) {
        console.log(error);
        res.sendStatus(500);
    }
};


const modifierContactInfo = async (req, res) => {
    console.log("req.body",req.body)
    const _id = req.params._id;
    const { siegeSocial, numeroTelephone,email,localisation,lienFacebook } = req.body;
    const modifiedContactInfo = {
        siegeSocial, numeroTelephone,email,localisation,lienFacebook
    };

    if (!modifiedContactInfo) {
        return res.sendStatus(402);
    }
    try {
        const contactInfo = await ContactInfo.findOneAndUpdate({ _id }, modifiedContactInfo, {
            new: true,
            runValidators: true,
        }).lean();
        if (!contactInfo) {
            return res.sendStatus(500);
        }
        res.send(contactInfo);
    } catch (error) {
        console.log(error);
        if (error instanceof mongoose.error.ValidationError) {
            return res.sendStatus(404);
        }
        return res.sendStatus(502);
    }
};


module.exports = {
    addContactInfo,
    getContactInfo,
    modifierContactInfo,
};
