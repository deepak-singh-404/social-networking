var express = require('express');
var { validateToken } = require('../middleware/authentication');
var router = express.Router();
var { createGroup, findGroup } = require("../controllers/group");

router.post("/", validateToken, createGroup)
router.get("/find", validateToken, findGroup)

module.exports = router;