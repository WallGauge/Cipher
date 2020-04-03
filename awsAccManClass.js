const AWS =             require('aws-sdk');
const fs =              require("fs");
const EventEmitter =    require('events');

const logitPrefix = 'cipher.awsAccMan | ';
var creds = {};
var iam = {};
var kms = {};

class awsAccMan extends EventEmitter {
    /**
     * This class is used to manage the AWS IAM login credentials.  
     * Its primary purpose is to insure the IAM secret is rotated every 90 days.  
     * To rotate first call getAccessKeyAge() to get the age of the IAM secret.  To replace with new key call rotateAccessKey()
     * 
     * emits 
     *  this.emit('iamReady')
     *  this.emit('iamError', err)
     *  this.emit('iamCredentialsUpdated')
     * 
     * @param {string} CredentialsFile File location of the AWS IMA credentials in JSON format 
     * @param {string} awsRegion This is your Amazon region (location of your AWS KMS account)
     */
    constructor(CredentialsFile =  __dirname + '/awsConfig.json', awsRegion = 'us-east-1'){
        super();
        this.userName = '';     //Amazon user name should match GDT network name.
        this.userID = '';       //Amazon unique user ID
        this.userArn = '';      //Amazon Resource Name
        this.userTags = {};     //Amazon Tags attached to this user
        this._credentialsFile = CredentialsFile
        this._region = awsRegion;
        this.haveCredentials = false;
        creds = new AWS.FileSystemCredentials(this._credentialsFile);  //https://docs.aws.amazon.com/AWSJavaScriptSDK/latest/AWS/FileSystemCredentials.html
        checkForCredentials(this._credentialsFile)
        .then(()=>{
            this.haveCredentials = true;
            iam = new AWS.IAM({accessKeyId: creds.accessKeyId, secretAccessKey: creds.secretAccessKey, region: this._region});
            kms = new AWS.KMS({accessKeyId: creds.accessKeyId, secretAccessKey: creds.secretAccessKey, region: this._region});
            getUser()
            .then((dObj)=>{
                this.userName = dObj.User.UserName
                this.userID = dObj.User.UserId
                this.userArn = dObj.User.Arn
                return this.getUserTags(this.userName)
            })
            .then(()=>{
                this.emit('iamReady');
            })
            
            .catch((err)=>{
                console.error('Error verifying credentials details follow:', err)
                this.emit('iamError', err);
            })
        })
        .catch((err)=>{
            console.error('Error: awsAccManClass error while checking for AWS IAM credentials.', err);
            this.emit('iamError', err);
        });
    };

    /** reloads IAM credentials
     * returns a promise
     */
    reloadCredentials(){
        return new Promise((resolve, reject)=>{
            creds = new AWS.FileSystemCredentials(this._credentialsFile);  //https://docs.aws.amazon.com/AWSJavaScriptSDK/latest/AWS/FileSystemCredentials.html
            checkForCredentials(this._credentialsFile)
            .then(()=>{
                this.haveCredentials = true;
                iam = new AWS.IAM({accessKeyId: creds.accessKeyId, secretAccessKey: creds.secretAccessKey, region: this._region});
                kms = new AWS.KMS({accessKeyId: creds.accessKeyId, secretAccessKey: creds.secretAccessKey, region: this._region});
                getUser()
                .then((dObj)=>{
                    this.userName = dObj.User.UserName
                    this.userID = dObj.User.UserId
                    this.userArn = dObj.User.Arn
                    resolve();
                })
                .catch((err)=>{
                    this.haveCredentials = false;
                    console.error('Error verifying credentials details follow:', err)
                    reject(err);
                })
            })
            .catch((err)=>{
                this.haveCredentials = false;
                console.error('Error: awsAccManClass error while reloading credentials for AWS IAM credentials.', err);
                reject(err);
            });
        });
    };

    /**
     * Gets the age of the IAM security credentials currently in use.  
     * Returns a promise with the age in number of days as a floating point
     * 
     */
    getAccessKeyAge(){
        return new Promise((resolve, reject)=>{
            if(this.haveCredentials) {
                getAccessKeyLastUsed(creds.accessKeyId)
                .then((data)=>{
                    this.userName = data.UserName;
                    return listAccessKeys(this.userName)
                })    
                .then((data)=>{
                    var keyCount = data.AccessKeyMetadata.length;
                    if(keyCount == 1){
                        var keyCreateDate = new Date(data.AccessKeyMetadata[0].CreateDate);
                        var keyAgeInDays = ((new Date((new Date()) - keyCreateDate)).getTime() / 86400000).toFixed(2)
                        logit('The AWS IAM access Key for '+ this.userName +' created on ' + keyCreateDate.toDateString() + ', it is '+ keyAgeInDays + ' days old.');
                        resolve(keyAgeInDays);
                    } else {
                        console.error('Error the AWS IAM account for ' + this.userName + ' is either missing or has more than one IAM access key.');
                        reject('Error the AWS IAM account for ' + this.userName + ' is either missing or has more than one IAM access key.');
                    };
                })
                .catch((err)=>{
                    console.error('Error getting access key information ', err);
                    reject('Getting access key information ' + err);
                });
            } else {
                console.error('AWS credentials missing. getAccessKeyInfo not allowed');
                reject('AWS credentials missing. getAccessKeyInfo not allowed');
            };
        });
    };

    /**
     * Rotates the current AWS IAM access key by requesting new key, saving it to the credentials file location,
     * and deleting the old key.f
     * Returns promise and emits: 
     *  emit('iamCredentialsUpdated');
     */
    rotateAccessKey(){
        return new Promise((resolve, reject)=>{
            if(this.haveCredentials) {
                logit('awsAccManClass is rotating access keys');
                getNewAccessKey()
                .then((data)=>{
                    var keyToDelete = creds.accessKeyId
                    saveNewAccessKey(data.AccessKey.AccessKeyId, data.AccessKey.SecretAccessKey);
                    return deleteAccessKey(keyToDelete)
                })    
                .then(()=>{
                    logit('AWS IAM key rotation complete.');
                    this.emit('iamCredentialsUpdated');
                    resolve();
                }) 
                .catch((err)=>{
                    console.error('Error rotating AWS IAM access credentials ', err);
                    reject('Error rotating AWS IAM access credentials ' + err)
                });
            } else {
                console.error('AWS credentials missing. rotateAccessKey not allowed');
                reject('AWS credentials missing. rotateAccessKey not allowed');
            };
        });
    };

    /** Creates new credentials file
     * This is a synchronous call.
     * Returns true or false 
     * 
     * @param {string} accessKeyId AWS IAM key ID
     * @param {string} secretAccessKey AWS IAM key secret
     */
    createCredentialsFile(accessKeyId = '', secretAccessKey = ''){
        logit('Creating new AWS IAM credentials file.')
        return saveNewAccessKey(accessKeyId, secretAccessKey)
    };

    /** Read userinformaiont for IAM account
     * Returns promise 
     * promise retuns obj for more details see https://docs.aws.amazon.com/AWSJavaScriptSDK/latest/AWS/IAM.html#getUser-property
     */
    getUserInfo(){
        return getUser()
    };

    /** Returs a promise and sets this.userTags 
     * IAM user tags are created when a AWS IAM user is created.  
     * 
     * @param {*} userName 
     */
    getUserTags(userName = ''){
        return new Promise((resolve, reject)=>{
            getUserTags(userName)
            .then((dObj)=>{
                var arrayOfTags = dObj.Tags;
                if(Array.isArray(arrayOfTags)){
                    arrayOfTags.forEach((val, ndx)=>{
                        this.userTags[val.Key] = val.Value
                    });
                };
                resolve();
            })
            .catch((err)=>{
                reject(err);
            });
        });
    };


    /**
     * This method will use the first cmkID passed to this class to encrypt a string or buffer up to 4096 bytes in size.
     * To encrypt larger amounts of data use the encryptionClass.js
     * 
     * This method does not use the key in the cmk.json file for encryption.  
     * Instead it uses a AWS Customer managed key referenced in the first key passed in the cmkIDs param during construction of this class.
     * 
     * returns promise with CiphertextBlob and parm
     * 
     * see https://docs.aws.amazon.com/AWSJavaScriptSDK/latest/AWS/KMS.html#encrypt-property 
     * For more inforamtion on encryptionContext see https://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html
     * 
     * @param {String} dataToEncrypt this is a string or buffer < 4096 bytes
     * @param {object} encContext is an optional encryptionContext key value pair. Set to null if not used
     * @param {String} cmkId is the AWS CMK ID to use for encryption.
     * @returns {Promise}
     */
    encrypt(dataToEncrypt = '', encContext = {"key":"value"}, cmkId = ''){
        return new Promise((resolve, reject)=>{
            var params = {};
            if(encContext == null){
                params = {
                    KeyId: cmkId,
                    Plaintext: dataToEncrypt
                };
            } else {
                params = {
                    KeyId: cmkId,
                    Plaintext: dataToEncrypt,
                    EncryptionContext: encContext
                };
            };
            kms.encrypt(params, (err, data) =>{
                if(err){
                    reject(err);
                } else {
                    resolve(data);
                };
            });
        });
    };

    /**
     * This method will decrypt data passed it in the ciphertextBlob parm.  The cipherTextBlob will have the AWS key ID used to encrypt the data. 
     * see https://docs.aws.amazon.com/AWSJavaScriptSDK/latest/AWS/KMS.html#decrypt-property
     * For more inforamtion on encryptionContext see https://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html
     * For an overview of the decrypt command see https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html
     * 
     * This method does not use the key in the cmk.json file for encryption.  
     * Instead it uses a AWS Customer managed key referenced in the first key passed in the cmkIDs param during construction of this class.
     * 
     * The encContext value must match the encContext value used to encrypt the data
     * 
     * @param {*} ciphertextBlob 
     * @param {object} encContext is an optional encryptionContext key value pair. Set to null if not used.
     * @returns {Promise}
     */
    decrypt(ciphertextBlob = '', encContext = {"key":"value"}){
        return new Promise((resolve, reject)=>{
            var params = {};
            if(encContext == null){
                params = {
                    CiphertextBlob: Buffer.from(ciphertextBlob),
                };
            } else {
                params = {
                    CiphertextBlob: Buffer.from(ciphertextBlob),
                    EncryptionContext: encContext
                };
            };
            kms.decrypt(params, (err, data)=>{
                if(err){
                    reject(err);
                } else {
                    resolve(data);
                };
            });
        });
    };

};

function checkForCredentials(fileName){
    return new Promise((resolve, reject)=>{
        fs.access(fileName, fs.constants.R_OK, (err)=>{
            if(err){
                reject(err);
            } else {
                resolve();
            };
        });
    });
};

function getNewAccessKey(){
    return new Promise((resolve, reject)=>{
        const params = {};
        iam.createAccessKey(params, function(err, data) {
            if (err){
                console.error('Error awsAccManClass getNewAccessKey: ', err); // an error occurred
                reject(err);
            } else {
                logit('new access key object received.');
                resolve(data);
            };
        });
    });
};

function saveNewAccessKey(keyID, keySecret){
    logit('saving new AWS config...');
    var awsCfgObj = {
        accessKeyId: keyID,
        secretAccessKey: keySecret
    };
    logit('Writting new awsConfig to ' + creds.filename);
    try{
        fs.writeFileSync(creds.filename, JSON.stringify(awsCfgObj));
    } catch (err) {
        console.error('Error saveNewAccessKey in awsAccManClass.js', err);
        return false;
    };
    return true;
};

function deleteAccessKey(keyID){
    logit('Deleting old access key ' + keyID);
    return new Promise((resolve, reject)=>{
        const params = {
            AccessKeyId: keyID
        };
        iam.deleteAccessKey(params, function(err, data) {
            if (err) {
                reject(err);
            } else {
                logit('Old Access Key deleted from AWS.');           // successful response
                resolve();
            };
        });
    });
};

function getAccessKeyLastUsed(keyID){
    return new Promise((resolve, reject)=>{
        const params = {
            AccessKeyId: keyID
        };
        iam.getAccessKeyLastUsed(params, function(err, data) {
            if (err) {
                reject(err);
            } else {
                resolve(data);
            };
        });
    });
};

function listAccessKeys(userName){
    return new Promise((resolve, reject)=>{
        const params = {
            UserName: userName
        };
        iam.listAccessKeys(params, function(err, data) {
            if (err) {
                reject(err);
            } else {
                resolve(data);
            };
        });
    });
};

/**
 * See https://docs.aws.amazon.com/AWSJavaScriptSDK/latest/AWS/IAM.html#getUser-property
 */
function getUser(){
    return new Promise((resolve, reject)=>{
        const params = {};
        iam.getUser(params, function(err, data) {
            if (err) {
                reject(err);
            } else {
                resolve(data);
            };
        });
    });
};

/**
 * See https://docs.aws.amazon.com/AWSJavaScriptSDK/latest/AWS/IAM.html#listUserTags-property
 * @param {*} userName 
 */
function getUserTags(userName = ''){
    return new Promise((resolve, reject)=>{
        const params = {
            UserName: userName
        };
        iam.listUserTags(params, function(err, data) {
            if (err) {
                reject(err);
            } else {
                resolve(data);
            };
        });
    });
};

function logit(txt = ''){
    console.debug(logitPrefix + txt)
};
module.exports = awsAccMan;