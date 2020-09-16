var Single = require('../models/single');

module.exports = {
    async getChats(req, res) {
        console.log(req.body)
        try {
            const data = await Single.find({ _id: req.params.id })
            return res.json(data)

        } catch (error) {
            console.log(error)

        }
    },
    // async addChats(req, res) {
    //     console.log(req.body)
    //     try {
    //         const data = await Single.create({ ...req.body });
    //         return res.json(data)

    //     } catch (error) {
    //         console.log(error)
    //         if (error.name === "MongoError") {
    //             return res.status(400).json({ message: error.message });
    //         }
    //         res.status(400).send(error);
    //     }
    // }

}