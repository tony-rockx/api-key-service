const crypto = require('crypto');
const axios = require('axios');

require('dotenv').config()

const apiKeyIP = process.env.APIKEY_IP || "http://localhost";
const apiKeyPort = process.env.APIKEY_PORT || "3888";

let isAuthorised = async function(req, res, next) {
  let url = apiKeyIP + ":" + apiKeyPort + '/authorisation';

  let data;
  if(req.method == "GET"){
    data = req.query;
  }else{
    data = req.body;
  }

  console.log("data",data)

  axios.post(url, data)
  .then(async function (response) {
    console.log("response", response["data"])
    if(response["data"]["authorisation"] == true){
      req.body.user = response["data"]["user"];

      return next();
    }else{
      res.status(500).send('Authentication fail')
    }
  })
  .catch(function (error) {
    console.log(error);
  });
}

let authEncryptHash = async function(apiSecret, data) {
  var promise = new Promise(async function(resolve, reject){

    let param = [];

    let dataParam = await authParseData(data);

    let stringToSign = await authSortData(dataParam);
    console.log("stringToSign: " + stringToSign)

    let hash = await authGenerateHash(apiSecret, stringToSign)
    console.log("hash: " + hash)

    resolve(hash)
  });

  return promise;
}


let authDecryptCheck = async function(apiSecret, data) {
  var promise = new Promise(async function(resolve, reject){

    let param = [];
    // extract signature from data

    let signature = data["signature"];
    let userApiKey = data["api_key"];

    if(signature !== undefined){
      let dataParam = await authParseData(data);

      let stringToSign = await authSortData(dataParam);
      console.log("stringToSign: " + stringToSign)

      let hash = await authGenerateHash(apiSecret, stringToSign)
      console.log("hash: " + hash)

      let match = await checkSignatureAndHash(hash, signature, userApiKey)

      console.log("match: " + match)

      resolve(match)
    }else{
      resolve(false)
      // Promise.reject("No signature");
    }

  });

  return promise;
}


let checkSignatureAndHash = async function(hash, signature, userApiKey) {
  var promise = new Promise(function(resolve, reject){
    let check = false;

    if(hash == signature){
      check = true;
    }

    resolve(check)
  });

  return promise;
}



let authParseData = async function(data) {
  var promise = new Promise(function(resolve, reject){
    // Remove signature
    let tempData = JSON.parse(JSON.stringify(data));

    delete tempData.signature;

    delete tempData.user;

    // Convert object to string
    let rawData = String(JSON.stringify(tempData));

    // Remove quotation
    rawData = rawData.replace(/\"/g, "");

    // Remove {}
    rawData = rawData.substring(1, rawData.length - 1);

    // Convert : to =
    rawData = rawData.replace(/:/g, '=');

    // Split entries into array
    let param = rawData.split(",");

    resolve(param)
  });

  return promise;
}

let authSortData = async function(param) {
  var promise = new Promise(function(resolve, reject){
    // make all character uppercase
    for(var i = 0; i<param.length; i++){
      param[i] = (param[i]).toUpperCase();
    }

    param.sort();

    let stringToSign = "";

    for(var i = 0; i<param.length; i++){
      if(i == 0){
        stringToSign += param[i]
      }else{
        stringToSign += "&" + param[i]
      }
    }

    resolve(stringToSign)
  });

  return promise;
}

let authGenerateHash = async function(apiSecret, string) {
  var promise = new Promise(function(resolve, reject){
    let apiSecretByte = Buffer.from(apiSecret, 'utf-8');
    let stringByte = Buffer.from(string, 'utf-8');

    const hash = crypto.createHmac('sha256', apiSecretByte)
                   .update(stringByte, "binary")
                   .digest('hex');

    resolve(hash)
  });

  return promise;
}

exports.isAuthorised = isAuthorised;
exports.authEncryptHash = authEncryptHash;
exports.authDecryptCheck = authDecryptCheck;
exports.authParseData = authParseData;
exports.authGenerateHash = authGenerateHash;
