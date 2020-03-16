var express = require('express')
var router = express.Router()

const axios = require('axios');
var moment = require('moment');

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

  var currentEpoch = moment().valueOf();
  console.log("currentEpoch", currentEpoch);

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
    let expirationEpoch = apiSecretAndUser[9];
    console.log("apiSecretAndUser", apiSecretAndUser);
    console.log("expirationEpoch", expirationEpoch);

    if(expirationEpoch > currentEpoch){
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
        "message": "api key expired"
      });
    }
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
  var expiration = req.body.expiration || "week";
  var permissionFeature = req.body.permission_feature || "";
  var permissionCoin = req.body.permission_coin || "";
  var permissionWallet = req.body.permission_wallet || "";
  var permissionNetwork = req.body.permission_network || "";

  var currentEpoch = moment().valueOf();
  console.log("currentEpoch", currentEpoch);

  let expirationTime = 604800;
  if(expiration == "week"){
    expirationTime = 604800000;
  }else if(expiration == "month"){
    expirationTime = 2629743000;
  }else if(expiration == "quarter"){
    expirationTime = 2629743000 * 3;
  }

  var expirationEpoch = currentEpoch + expirationTime; // 3 month

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

  let result = await tx.addAccountToDB(user, email, apiKeyPrefix, apiKeyPostfix, apiKeyHash, apiSecret, expirationEpoch, permissionFeature, permissionCoin, permissionWallet, permissionNetwork);

  return res.json({
    "api_key": apiKey,
    "api_secret": apiSecret,
    "result": result
  });
}));

// since user might have multiple keys, the permission level will be based on the keys used (that match with signature). It can however delete key under the same user & email (unsafe?)

// there should be 2 ways of deleting keys.
// normal user can only delete their own key
// admin user can delete anybody's key
// * api key or secret shouldn't be needed else there'll be no way to delete key if they lose it
router.post('/account/delete', asyncHandler(async (req, res, next) => {
  var user = req.body.user;
  var email = req.body.email;
  // var apiKey = req.body.api_key;

  // console.log('DELETE /account/', user, email, apiKey);

  // let signature = "temp exist"
  //
  // if(signature){
  //   let apiKeyHash = await tx.generateApiKeyHash(apiKey);
  //
  //   console.log("apiKeyHash", apiKeyHash);
  //
  //   let apiSecretAndUser = await tx.retrieveApiSecretAndUser(apiKey, apiKeyHash);
  //
  //   console.log(apiSecretAndUser);

    // if(apiSecretAndUser !== "fail"){

  let result = await tx.deleteKey(user, email);

  return res.json({
    "status": 200,
    "message": "api key deleted"
  });
  //   }else{
  //     return res.json({
  //       "status": 204,
  //       "message": "access restricted"
  //     });
  //   }
  //
  // }else{
  //   return res.json({
  //     "status": 400,
  //     "message": "no signature found"
  //   });
  // }
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
