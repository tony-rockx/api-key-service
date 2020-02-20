var express = require('express')
var router = express.Router()

const axios = require('axios');

//require('dotenv').config()

var auth = require('../core/auth.js');
var tx = require('../core/transaction.js');

const asyncHandler = fn => (req, res, next) =>
  Promise
    .resolve(fn(req, res, next))
    .catch(next)


router.get('/test', (req, res) => {
  return res.send('test');
});

// create key
// delete key
// edit permission
// check permission
// check authorisation

// hash api key and secret when store in db

router.post('/authorisation/', asyncHandler(async (req, res, next) => {
  var apiKey = req.body.api_key;
  var data = req.body;
  var signature = req.body.signature;

  if(signature){
    console.log("data", data);

    let apiKeyHash = await tx.generateApiKeyHash(apiKey);

    console.log("apiKeyHash", apiKeyHash);

    let apiSecretAndUser = await tx.retrieveApiSecretAndUser(apiKey, apiKeyHash);
    let apiSecret = apiSecretAndUser[0];
    let apiUser = apiSecretAndUser[1];
    let apiUserId = apiSecretAndUser[2];

    console.log("apiSecret", apiSecret);
    console.log("apiUser", apiUser);

    let access = await auth.authDecryptCheck(apiSecret, data);

    console.log("access", access);
    // use API secret to see if can get the same signature as that passed in

    return res.json({
      "authorisation": access,
      "user": apiUser,
      "user_id": apiUserId
    });
  }else{
    return res.json({
      "status": 400,
      "message": "no signature found"
    });
  }
}));


router.post('/account/', asyncHandler(async (req, res, next) => {
  var user = req.body.user;
  var email = req.body.email;

  let apiKey = await tx.generateApiKey();
  let apiSecret = await tx.generateApiSecret();

  let apiKeyPrefix = apiKey.substring(0, 5);
  let apiKeyPostfix = apiKey.substring(apiKey.length - 5, apiKey.length);

  console.log(apiKeyPrefix, apiKeyPostfix);

  let apiKeyHash = await tx.generateApiKeyHash(apiKey);

  console.log(apiKeyHash);

  let result = await tx.addAccountToDB(user, email, apiKeyPrefix, apiKeyPostfix, apiKeyHash, apiSecret, "low");

  return res.json({
    "api_key": apiKey,
    "api_secret": apiSecret,
    "result": result
  });
}));

router.get('/account/', asyncHandler(async (req, res, next) => {
  let result = await tx.getAccountFromDB();

  return res.json({
    "result": result
  });
}));

// router.delete('/address/', asyncHandler(async (req, res, next) => {
//   var address = req.query.address;
//   let hash = await checksum.checksumGenerate(address);
//
//   return res.json({
//     "checksum": hash
//   });
// }));


module.exports = router
