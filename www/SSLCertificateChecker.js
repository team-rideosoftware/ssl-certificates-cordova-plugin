"use strict";
var exec = require('cordova/exec');

function SSLCertificates() {
}

SSLCertificates.prototype.check = function (successCallback, errorCallback, serverURL, allowedSHA1FingerprintOrArray, allowedSHA1FingerprintAlt) {
  if (typeof errorCallback != "function") {
    console.log("SSLCertificates.find failure: errorCallback parameter must be a function");
    return
  }

  if (typeof successCallback != "function") {
    console.log("SSLCertificates.find failure: successCallback parameter must be a function");
    return
  }

  // if an array is not passed, transform the input into one
  var fpArr = [];
  if (allowedSHA1FingerprintOrArray !== undefined) {
      if (typeof allowedSHA1FingerprintOrArray == "string") {
          fpArr.push(allowedSHA1FingerprintOrArray);
      } else {
          fpArr = allowedSHA1FingerprintOrArray.slice(0);
      }
  }
  if (allowedSHA1FingerprintAlt !== undefined) {
      fpArr.push(allowedSHA1FingerprintAlt);
  }
  exec(successCallback, errorCallback, "SSLCertificates", "check", [serverURL, false, fpArr]);
};

SSLCertificates.prototype.checkInCertChain = function (successCallback, errorCallback, serverURL, allowedSHA1FingerprintOrArray, allowedSHA1FingerprintAlt) {
  if (typeof errorCallback != "function") {
    console.log("SSLCertificates.find failure: errorCallback parameter must be a function");
    return
  }
  errorCallback("This function has been removed in versions higher than 4.0.0 because it's considered too insecure.");
  /*
  if (typeof successCallback != "function") {
    console.log("SSLCertificates.find failure: successCallback parameter must be a function");
    return
  }
  // if an array is not passed, transform the input into one
  var fpArr = [];
  if (allowedSHA1FingerprintOrArray !== undefined) {
    if (typeof allowedSHA1FingerprintOrArray == "string") {
      fpArr.push(allowedSHA1FingerprintOrArray);
    } else {
      fpArr = allowedSHA1FingerprintOrArray.slice(0);
    }
  }
  if (allowedSHA1FingerprintAlt !== undefined) {
    fpArr.push(allowedSHA1FingerprintAlt);
  }
  cordova.exec(successCallback, errorCallback, "SSLCertificates", "check", [serverURL, true, fpArr]);
  */
};

var sslCertificates = new SSLCertificates();
module.exports = sslCertificates;
