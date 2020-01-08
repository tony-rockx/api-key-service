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

let addAccountToDB = async function(user, email, apiKeyPrefix, apiKeyPostfix, apiKeyHash, apiSecret, permission) {
  var promise = new Promise(function(resolve, reject){
    let query = 'INSERT INTO `' + 'api_keys' + '` (user, email, api_key_prefix, api_key_postfix, api_key_hash, api_secret, permission) VALUES("' + user +'", "' + email +'", "' + apiKeyPrefix +'", "' + apiKeyPostfix +'", "' + apiKeyHash +'", "' + apiSecret +'", "' + permission +'");'

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


let retrieveApiSecret = async function(apiKey, apiKeyHash) {

  var promise = new Promise(function(resolve, reject){
    let apiKeyPrefix = apiKey.substring(0, 5);
    let apiKeyPostfix = apiKey.substring(apiKey.length - 5, apiKey.length);

    let query = 'SELECT * FROM `' + 'api_keys' + '` WHERE api_key_prefix="' + apiKeyPrefix +'" AND api_key_postfix="' + apiKeyPostfix +'";'

    db.query(query, (err, result) => {
        if (err) {
            // return result.status(500).send(err);
            resolve("fail");
        }

        if(result[0]["api_key_hash"] == apiKeyHash){
          console.log(result[0]["api_secret"]);
          resolve(result[0]["api_secret"]);
        }

    });
  });
  return promise;
}


exports.generateApiKey = generateApiKey;
exports.generateApiSecret = generateApiSecret;
exports.generateApiKeyHash = generateApiKeyHash;
exports.addAccountToDB = addAccountToDB;
exports.retrieveApiSecret = retrieveApiSecret;
