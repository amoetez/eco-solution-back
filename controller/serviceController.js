const { findById } = require('../models/Service.js');
const Service = require('../models/Service.js');
const path = require('path');
const fs = require('fs');

const addService = async (req, res) => {
    const { titre, description } = req.body;
    if(!req.file){return res.status(400).send("problem with the sended data of object service")}
    const image = path.basename(req.file.path);
    const service = new Service({ titre, description, image });

    try {
        await service.save();
        res.send(service);
    } catch (e) {
        res.status(400).send("mo7sen");
    }
};

const getServiceById = async (req, res) => {
    try {
        let result = await Service.findById(req.params._id);
        if (!result) {
            return res.sendStatus(404);

        }
        res.status(200).json(result);
    } catch (error) {
        console.log(error);
        res.sendStatus(500);
    }
};

const getServices = async (req, res) => {
    try {
        let result = await Service.find();
        console.log(result);
        if (!result) {
            return res.sendStatus(404);
        }
        res.status(200).json(result);
    } catch (error) {
        console.log(error);
        res.sendStatus(500);
    }
};
const modifierService = async (req, res) => {
    const _id = req.params._id;
    const { description, titre } = req.body;
    const modifiedService = {
        description,titre
    };
    if (req.file !== undefined) {
        const image = path.basename(req.file.path)
        modifiedService['image'] = image;
    }
    
    if (titre==='' || description==='' || !modifiedService) {
        return res.sendStatus(402);
    }
    try {
        let service = await Service.findOneAndUpdate({ _id }, modifiedService, {
            new: true,
            runValidators: true,
        }).lean();
        if (!service) {
            return res.sendStatus(500);
        }
        res.send(service);
    } catch (error) {
        console.log(error);
        if (error instanceof mongoose.error.ValidationError) {
            return res.sendStatus(404);
        }
        return res.sendStatus(502);
    }
};

const deleteById = async (req, res) => {
    try {
        const _id = req.params._id;
        const service = await Service.findById(_id);
        const imagePath = path.join(__dirname,'..','uploads','imageService',service.image);
        const result = await Service.deleteOne({ _id });
        if (result.deletedCount === 0) {
            return res.sendStatus(500);
        }
        if (service.image !== undefined) {
            fs.unlink(imagePath, (error) => {
                if (error) {
                    console.log(error);
                    return;
                }
                console.log(`${imagePath} removed with success`);
            })
        }

        res.sendStatus(200);
    } catch (error) {
        res.sendStatus(500);
    }
};

module.exports = {
    addService,
    getServiceById,
    getServices,
    modifierService,
    deleteById,
};
