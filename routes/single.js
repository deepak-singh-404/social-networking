var express = require('express');
var { validateToken } = require('../middleware/authentication');
var router = express.Router();
var { getChats } = require("../controllers/single");

router.get("/", validateToken, getChats)
//router.post("/addChats",  addChats)
module.exports = router;