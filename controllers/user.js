var User = require("../models/user");
var bcrypt = require('bcrypt');
var { createToken } = require('../middleware/authentication');
const validator = require('validator');
module.exports = {
    async userRegister(req, res) {
        try {
            req.body.password = await bcrypt.hash(req.body.password, 10);
            await User.create({ ...req.body });
            return res.json({ success: true, message: 'user register successfully' })
        } catch (error) {
            console.log(error)
            if (error.name === "MongoError") {
                return res.status(400).json({ message: error.message });
            }
            res.status(400).send(error);
        }
    },
    async userLogin(req, res) {
        try {
            const email = req.body.email;
            const password = req.body.password;
            const user = await User.findOne({ email });
            if (!user) {
                return res.status(400).json({ error: "User does not exists" })
            }
            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                return res.status(404).json({ error: "Invalid Password" });
            }
            var token = await createToken(user);
            res.cookie('token', token);
            return res.json({
                firstName: user.firstName,
                lastName: user.lastName,
                email: user.email,
                id: user._id,
                photoURL: user.photoURL,
                token: token
            });
        } catch (error) {
            console.log(error)
            if (error.name === "MongoError") {
                return res.status(400).send(`Validation Error: ${error.message}`)
            }
            res.status(400).send(error);

        }
    },
    async userLogout(req, res) {
        try {
            res.cookie('token', { expires: Date.now() });
            return res.json({ message: "logged out" })
        } catch (error) {
            console.log(error)
            res.status(400).send(error)

        }
    },
    async getallUser(req, res) {
        try {
            var result = await User.find({ _id: { $ne: req.user.id } });
            res.json(result)
        } catch (error) {
            console.log(error)
            res.status(400).send(error)

        }
    },
    async getoneUser(req, res) {
        try {
            var result = await User.find({ _id: req.params.id })
            res.json(result);
        } catch (error) {
            console.log(error)
            res.status(400).send(error)

        }
    },
    async updateUser(req, res) {
        try {
            var result = await User.updateOne({ _id: req.params.id }, { ...req.body })
            res.json(result)
        } catch (error) {
            console.log(error)
            res.status(400).send(error)
        }
    },
    async searchUser(req, res) {
        try {
            console.log(req.body)
            var result = await User.find({ $or: [{ firstName: { "$regex": req.body.searchQuery, "$options": "i" } }, { lastName: { "$regex": req.body.searchQuery, "$options": "i" } }] }, { firstName: 1, lastName: 1 });
            return res.json(result);
        } catch (error) {
            // console.log(error)
            return res.status(400).json(error);
        }
    },
    async findFriends(req, res) {
        try {
            if (req.user.id) {
                var result = await User.findOne({ _id: req.user.id }, { friends: 1, _id: 0 }).populate("friends").exec();
                return res.json(result)
            } else {
                res.status(400).json({ error: "Not a valid token" })
            }
        } catch (error) {
            console.log(error)
            res.status(400).json({ error: "Not able to find friend" })

        }
    }
}