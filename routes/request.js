var express = require('express');
var { validateToken } = require('../middleware/authentication');
var router = express.Router();
var { sendRequest, getAllRequest, updateRequest, findFriends } = require('../controllers/request');

router.post('/', validateToken, sendRequest);
router.get("/all", validateToken, getAllRequest);
router.put('/update', validateToken, updateRequest)
router.get("/friend", validateToken, findFriends)
module.exports = router;
