var Group = require("../models/group");
const User = require("../models/user");

module.exports = {
    async createGroup(req, res) {
        try {
            const result = await Group.create({ ...req.body, owner: req.user.id })
            console.log(result)
            return res.json({ success: true, message: 'Group created successfully' })
        } catch (error) {
            console.log(error);
            if (error.name === "MongoError") {
                return res.status(400).send(`Validation Error: ${error.message}`)
            }
            res.status(400).send(error);
        }

    },
    async findGroup(req, res) {
        try {
            var result = await Group.find({ $or: [{ owner: req.user.id }, { member: req.user.id }] });
            return res.json(result)
        } catch (error) {
            console.log(error)
            return res.status(400).send({ message: "Not able to find friends" })
        }
    }
}