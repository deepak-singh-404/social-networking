var Request = require('../models/request');
var { createToken } = require('../middleware/authentication');
const request = require('../models/request');
const User = require("../models/user");
const Group = require("../models/group");
module.exports = {
    async sendRequest(req, res) {
        try {
            let query = { receiver: req.body.receiver };
            if (req.body.groupId) {
                query.groupId = req.body.groupId;
            }
            else {
                query.sender = req.body.sender
            }
            const data = await Request.findOne(query);

            if (data !== null) {
                return res.status(400).json({ error: "request already sent" })
            }

            await Request.create({ ...req.body });
            return res.json({ message: 'request sent successfully' });

        } catch (error) {
            console.log(error)
            return res.status(400).json({ error: 'failed to send request' })
        }
    },
    async getAllRequest(req, res) {
        try {
            var result = await request.find({ receiver: req.user.id, isAccepted: false, isReject: false }, { sender: 1, groupId: 1 }).populate('sender', ['firstName', 'lastName', 'photoURL']).populate('groupId', ['photoURL', 'groupName']).exec();
            res.json(result)
        } catch (error) {
            console.log(error)
            res.status(400).send(error)
        }
    },
    async updateRequest(req, res) {
        console.log(req.body)
        try {
            await Request.updateOne({ _id: req.body.id }, { ...req.body })
            if (req.body.isAccepted === true) {
                console.log(req.body);
                let query = [];
                if (req.body.friend) {
                    query = [
                        User.updateOne({ _id: req.user.id }, { $addToSet: { friends: req.body.friend } }),
                        User.updateOne({ _id: req.body.friend }, { $addToSet: { friends: req.user.id } }),
                    ]
                } else {
                    query = [
                        User.updateOne({ _id: req.user.id }, { $addToSet: { group: req.body.groupId } }),
                        Group.updateOne({ _id: req.body.groupId }, { $addToSet: { member: req.user.id } }),
                    ]
                }
                const data = await Promise.all(query);
            }
            return res.json({ message: "update success" })
        } catch (error) {
            console.log(error)
            res.status(400).json({ error: "failed to updated request" })
        }
    },
    async findFriends(req, res) {
        try {
            var result = await User.findOne({ _id: req.user.id }, { friends: 1, _id: 0 }).populate("friends", ['firstName', 'lastName', 'createdAt', 'photoURL','socketId']).exec();
            res.json(result)
        } catch (error) {
            console.log(error)
            res.status(400).json({ error: "Not able to find friend" })

        }
    },
    // async sendGroupRequest(req, res) {
    //     console.log(req.body)
    //     try {
    //         const data = await Request.findOne({ groupId: req.body.groupId, receiver: req.body.receiver })
    //         if (data !== null) {
    //             return res.status(400).json({ error: "request already sent" })
    //         }

    //         await Request.create({ ...req.body });
    //         return res.json({ message: 'request sent successfully' });

    //     } catch (error) {
    //         console.log(error)
    //         res.status(400).json({ error: "Not able to send request" })
    //     }
    // }
}