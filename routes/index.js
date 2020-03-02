var express = require('express')
var router = express.Router()

const axios = require('axios');

var auth = require('../core/auth.js');
var tx = require('../core/transaction.js');

const asyncHandler = fn => (req, res, next) =>
  Promise
    .resolve(fn(req, res, next))
    .catch(next)


router.get('/test', (req, res) => {
  return res.json({
    "status": 200,
    "data": "test"
  });
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

  // signature not being used to authentication?
  if(signature){
    console.log("data", data);

    let apiKeyHash = await tx.generateApiKeyHash(apiKey);

    console.log("apiKeyHash", apiKeyHash);

    let apiSecretAndUser = await tx.retrieveApiSecretAndUser(apiKey, apiKeyHash);
    let apiSecret = apiSecretAndUser[0];
    let apiUser = apiSecretAndUser[1];
    let apiUserId = apiSecretAndUser[2];
    let email = apiSecretAndUser[3];
    let permissionWallet = apiSecretAndUser[4];
    let permissionCoin = apiSecretAndUser[5];
    let permissionFeature = apiSecretAndUser[6];
    let permissionNetwork = apiSecretAndUser[7];
    let adminRights = apiSecretAndUser[8];

    console.log("apiSecret", apiSecret);
    console.log("apiUser", apiUser);

    let access = await auth.authDecryptCheck(apiSecret, data);

    console.log("access", access);
    // use API secret to see if can get the same signature as that passed in

    return res.json({
      "authorisation": access,
      "user": apiUser,
      "user_id": apiUserId,
      "email": email,
      "permission_wallet": permissionWallet,
      "permission_coin": permissionCoin,
      "permission_feature": permissionFeature,
      "permission_network": permissionNetwork,
      "admin_rights": adminRights
    });
  }else{
    return res.json({
      "status": 400,
      "message": "no signature found"
    });
  }
}));

router.post('/permission/', asyncHandler(async (req, res, next) => {
  var apiKey = req.body.api_key;
  var permissionType = req.body.permission_type;
  var permissionData = req.body.permission_data;
  var data = req.body;
  var signature = req.body.signature;
//
//   if(signature){
//     console.log("data", data);
//
    let apiKeyHash = await tx.generateApiKeyHash(apiKey);

    console.log("apiKeyHash", apiKeyHash);

    let result = await tx.updatePermission(apiKeyHash, permissionType, permissionData);

    return res.json({
      "status": 200,
      "message": "permission updated"
    });
//   }else{
//     return res.json({
//       "status": 400,
//       "message": "no signature found"
//     });
//   }
}));

// MAY need some authentication at some point
router.post('/account/', asyncHandler(async (req, res, next) => {
  var user = req.body.user;
  var email = req.body.email;

  let countResult = await tx.retrieveCountFromDB(email);
  let count  = countResult[0]["COUNT(*)"];
  console.log("current api keys count is", count);

  if (count >= 5) {
    return res.json({
      "status": 400,
      "message": "can't set more than 5 api keys"
    });
  }

  let apiKey = await tx.generateApiKey();
  let apiSecret = await tx.generateApiSecret();

  let apiKeyPrefix = apiKey.substring(0, 5);
  let apiKeyPostfix = apiKey.substring(apiKey.length - 5, apiKey.length);

  console.log(apiKeyPrefix, apiKeyPostfix);

  let apiKeyHash = await tx.generateApiKeyHash(apiKey);

  console.log(apiKeyHash);

  let result = await tx.addAccountToDB(user, email, apiKeyPrefix, apiKeyPostfix, apiKeyHash, apiSecret);

  return res.json({
    "api_key": apiKey,
    "api_secret": apiSecret,
    "result": result
  });
}));

// since user might have multiple keys, the permission level will be based on the keys used (that match with signature). It can however delete key under the same user & email (unsafe?)
router.post('/account/delete', asyncHandler(async (req, res, next) => {
  var user = req.body.user;
  var email = req.body.email;
  var apiKey = req.body.api_key;

  console.log('DELETE /account/', user, email, apiKey);

  let signature = "temp exist"

  if(signature){
    let apiKeyHash = await tx.generateApiKeyHash(apiKey);

    console.log("apiKeyHash", apiKeyHash);

    let apiSecretAndUser = await tx.retrieveApiSecretAndUser(apiKey, apiKeyHash);

    console.log(apiSecretAndUser);

    if(apiSecretAndUser !== "fail"){

      let result = await tx.deleteKey(user, email, apiKeyHash);

      return res.json({
        "status": 200,
        "message": "api key deleted"
      });
    }else{
    return res.json({
      "status": 204,
      "message": "access restricted"
    });
    }

  }else{
    return res.json({
      "status": 400,
      "message": "no signature found"
    });
  }
}));

// MUST need some authentication at some point
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
