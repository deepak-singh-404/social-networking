var express = require('express');
var { validateToken } = require('../middleware/authentication');
var router = express.Router();
var { findMessage, findSingleChat } = require("../controllers/chat");

router.get("/:groupId", validateToken, findMessage)
router.get("/single/:friendId", validateToken, findSingleChat);
module.exports = router;