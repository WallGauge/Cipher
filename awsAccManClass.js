const AWS =             require('aws-sdk');
const fs =              require("fs");
const EventEmitter =    require('events');

var creds = {};
var iam = {};

/**
 * This class is used to manage the AWS IAM login credentials.  
 * Its primary purpose is to insure the IAM secret is rotated every 90 days.  
 * To rotate first call getAccessKeyAge() to get the age of the IAM secret.  To replace with new key call rotateAccessKey()
 * 
 * emits 
 *  this.emit('iamReady')
 *  this.emit('iamCredentialsUpdated')
 *  this.emit('Error')
 * 
 * @param {string} CredentialsFile File location of the AWS IMA credentials in JSON format 
 * @param {string} awsRegion This is your Amazon region (location of your AWS KMS account)
 */
class awsAccMan extends EventEmitter {
    constructor(CredentialsFile =  __dirname + '/awsConfig.json', awsRegion = 'us-east-1'){
        super();
        this.userName = '';
        this._credentialsFile = CredentialsFile
        this._region = awsRegion;
        this.haveCredentials = false;
        creds = new AWS.FileSystemCredentials(this._credentialsFile);  //https://docs.aws.amazon.com/AWSJavaScriptSDK/latest/AWS/FileSystemCredentials.html
        checkForCredentials(this._credentialsFile)
        .then(()=>{
            this.haveCredentials = true;
            iam = new AWS.IAM({
                accessKeyId: creds.accessKeyId,            //credentials for your IAM user
                secretAccessKey: creds.secretAccessKey,    //credentials for your IAM user
                region: this._region
            });
            this.emit('iamReady');
        })
        .catch((err)=>{
            console.error('Error: awsAccManClass error while checking for AWS IAM credentials.', err);
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
                        console.debug('The AWS IAM access Key for '+ this.userName +' created on ' + keyCreateDate.toDateString() + ', it is '+ keyAgeInDays + ' days old.');
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
                console.debug('awsAccManClass is rotating access keys');
                getNewAccessKey()
                .then((data)=>{
                    var keyToDelete = creds.accessKeyId
                    saveNewAccessKey(data.AccessKey.AccessKeyId, data.AccessKey.SecretAccessKey);
                    return deleteAccessKey(keyToDelete)
                })    
                .then(()=>{
                    console.debug('AWS IAM key rotation complete.');
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
                console.debug('new access key object received.');
                resolve(data);
            };
        });
    });
};

function saveNewAccessKey(keyID, keySecret){
    console.debug('saving new AWS config...');
    var awsCfgObj = {
        accessKeyId: keyID,
        secretAccessKey: keySecret
    };
    console.debug('Writting new awsConfig to ' + creds.filename);
    fs.writeFileSync(creds.filename, JSON.stringify(awsCfgObj));
};

function deleteAccessKey(keyID){
    console.debug('Deleting old access key ' + keyID);
    return new Promise((resolve, reject)=>{
        const params = {
            AccessKeyId: keyID
        };
        iam.deleteAccessKey(params, function(err, data) {
            if (err) {
                console.error('Error deletAccessKey ', err); 
                reject(err);
            } else {
                console.debug('Old Access Key deleted from AWS.');           // successful response
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
                console.error('Error getAccessKeyUser ', err,); 
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
                console.error('Error listAccessKeys ', err); 
                reject(err);
            } else {
                resolve(data);
            };
        });
    });
};

module.exports = awsAccMan;