var Chat = require('../models/chat');
var { createToken } = require('../middleware/authentication');

module.exports = {
    async findMessage(req, res) {
        try {
            const data = await Chat.find({ groupId: req.params.groupId })
            return res.json(data)

        } catch (error) {
            console.log(error)

        }
    },
    async findSingleChat(req, res) {
        let chatId = "";
       if(req.user.id > req.params.friendId){
          chatId = req.user.id+'-'+req.params.friendId;
       }else{
        chatId = req.params.friendId+'-'+req.user.id;
       }

        console.log(chatId)
        try {
            const data = await Chat.find({ chatId });
            return res.json(data)
        } catch (error) {
            console.log(error)

        }

    }
}