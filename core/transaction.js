const uuidv4 = require('uuid/v4');
const cryptoRandomString = require('crypto-random-string');
const crypto = require('crypto');


require('dotenv').config()

var database = require('./db.js');


global.db = database.setupDB(
  process.env.DB_HOST,
  process.env.DB_USER,
  process.env.DB_PASSWORD,
  process.env.DB_DATABASE
);


let generateApiKey = async function() {
  var promise = new Promise(function(resolve, reject){
    resolve(uuidv4());
  });
  return promise;
}

let generateApiSecret = async function() {
  var promise = new Promise(function(resolve, reject){
    resolve(cryptoRandomString({length: 64}));
  });
  return promise;
}

let generateApiKeyHash = async function(apiKey) {
  var promise = new Promise(function(resolve, reject){
    let hash = apiKey;

    for(var i=0; i<5; i++){
      hash = crypto.createHash('sha256').update(hash).digest('hex');
    }

    resolve(hash)
  });
  return promise;
}


let getAccountFromDB = async function() {
  var promise = new Promise(function(resolve, reject){
    let query = 'SELECT id, date, user, email, api_key_prefix, api_key_postfix, expiration_epoch FROM `' + 'api_keys' + '`;'

    db.query(query, (err, result) => {
        if (err) {
            // return result.status(500).send(err);
            resolve("fail");
        }

        console.log(result)

        resolve(result);
    });
  });
  return promise;
}

let addAccountToDB = async function(user, email, apiKeyPrefix, apiKeyPostfix, apiKeyHash, apiSecret, epoch, permissionFeature, permissionCoin, permissionWallet, permissionNetwork) {
  var promise = new Promise(function(resolve, reject){
    let query = 'INSERT INTO `' + 'api_keys' + '` (user, email, api_key_prefix, api_key_postfix, api_key_hash, api_secret, permission_wallet, permission_coin, permission_feature, permission_network, admin_rights, expiration_epoch) VALUES("' + user +'", "' + email +'", "' + apiKeyPrefix +'", "' + apiKeyPostfix +'", "' + apiKeyHash +'", "' + apiSecret +'", "' + permissionWallet +'", "' + permissionCoin +'", "' + permissionFeature +'", "' + permissionNetwork +'", false, "' + epoch +'");'

    db.query(query, (err, result) => {
        if (err) {
            // return result.status(500).send(err);
            resolve("fail");
        }

        resolve("success");
    });
  });
  return promise;
}

let retrieveCountFromDB = async function(email) {
  var promise = new Promise(function(resolve, reject) {
    //let query = 'SELECT email, count FROM `' + 'api_keys_count' + '`;'
    let query = 'SELECT COUNT(*) FROM `' + 'api_keys' + '` WHERE `email`="' + email +'";'
    //SELECT COUNT(*) FROM api_keys WHERE email = 'xiaomeng@rockx.com';
    db.query(query, (err, result) => {
      if(err) {
        resolve("fail");
      }
      //console.log(result);
      resolve(result);
    });
  });
  return promise;
}

let retrieveApiSecretAndUser = async function(apiKey, apiKeyHash) {

  var promise = new Promise(function(resolve, reject){
    let apiKeyPrefix = apiKey.substring(0, 5);
    let apiKeyPostfix = apiKey.substring(apiKey.length - 5, apiKey.length);

    let query = 'SELECT * FROM `' + 'api_keys' + '` WHERE api_key_prefix="' + apiKeyPrefix +'" AND api_key_postfix="' + apiKeyPostfix +'";'

    db.query(query, (err, result) => {
        if (err) {
            // return result.status(500).send(err);
            resolve("fail");
        }

        if(result.length > 0){
          if(result[0]["api_key_hash"] == apiKeyHash){
            console.log(result[0]["id"]);
            console.log(result[0]["api_secret"]);
            console.log(result[0]["user"]);
            resolve([result[0]["api_secret"], result[0]["user"], result[0]["id"], result[0]["email"], result[0]["permission_wallet"], result[0]["permission_coin"], result[0]["permission_feature"], result[0]["permission_network"], result[0]["admin_rights"], result[0]["expiration_epoch"]]);
          }else{
            resolve("fail");
          }
        }else{
          resolve("fail");
        }

    });
  });
  return promise;
}


let deleteKey = async function(user, email) {
  var promise = new Promise(function(resolve, reject){
    let query = 'DELETE FROM `' + 'api_keys' + '` WHERE user="' + user +'" AND email="' + email +'";'

    db.query(query, (err, result) => {
        if (err) {
            // return result.status(500).send(err);
            resolve("fail");
        }

        console.log(result);
        resolve(result);
    });
  });
  return promise;
}


let updatePermission = async function(apiKeyHash, permissionType, permissionData) {
  let columnName = ""
  if(permissionType == "wallet"){
    columnName = "permission_wallet";
  }else if(permissionType == "coin"){
    columnName = "permission_coin";
  }else if(permissionType == "feature"){
    columnName = "permission_feature";
  }else if(permissionType == "network"){
    columnName = "permission_network";
  }
  var promise = new Promise(function(resolve, reject){
    let query = "UPDATE `" + 'api_keys' + "` SET `" + columnName + "` = '" + permissionData + "' WHERE `api_key_hash` = '" + apiKeyHash + "'";
    // UPDATE `api_keys` SET `permission_coin` = 'btc,eth,atom,iotex' WHERE `api_key_hash`='db865b194493bdaad45db03a1db705ac6c2ab8319314ecc65e9c8a4381ebe578';

    db.query(query, (err, result) => {
        if (err) {
            // return result.status(500).send(err);
            resolve("fail");
        }

        console.log(result);
        resolve(result);
    });
  });
  return promise;
}

exports.generateApiKey = generateApiKey;
exports.generateApiSecret = generateApiSecret;
exports.generateApiKeyHash = generateApiKeyHash;
exports.addAccountToDB = addAccountToDB;
exports.getAccountFromDB = getAccountFromDB;
exports.retrieveCountFromDB = retrieveCountFromDB;
exports.retrieveApiSecretAndUser = retrieveApiSecretAndUser;
exports.deleteKey = deleteKey;
exports.updatePermission = updatePermission;
