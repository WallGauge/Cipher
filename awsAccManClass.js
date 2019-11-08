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
            console.log('Error: awsAccManClass error while checking for AWS IAM credentials.');
            console.log(err);
        });
    };
    /**
     * Gets the age of the IAM security credentials currently in use.  
     * Returns a promise withg the age in number of days as a floating point
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
                        console.log('The AWS IAM access Key for '+ this.userName +' created on ' + keyCreateDate.toDateString() + ', it is '+ keyAgeInDays + ' days old.');
                        resolve(keyAgeInDays);
                    } else {
                        console.log('Error the AWS IAM account for ' + this.userName + ' is either missing or has more than one IAM access key.');
                        reject('Error the AWS IAM account for ' + this.userName + ' is either missing or has more than one IAM access key.');
                    };
                })
                .catch((err)=>{
                    console.log('Error getting access key information ' + err);
                    reject('Getting access key information ' + err);
                });
            } else {
                console.log('AWS credentials missing. getAccessKeyInfo not allowed');
                reject('AWS credentials missing. getAccessKeyInfo not allowed');
            };
        });
    };

    /**
     * Rotates the current AWS IAM access key by requesting new key, saving it to the credentials file location,
     * and deleting the old key.
     * emits: 
     *  emit('iamCredentialsUpdated');
     */
    rotateAccessKey(){
        if(this.haveCredentials) {
            console.log('awsAccManClass is rotating access keys');
            getNewAccessKey()
            .then((data)=>{
                var keyToDelete = creds.accessKeyId
                saveNewAccessKey(data.AccessKey.AccessKeyId, data.AccessKey.SecretAccessKey);
                return deleteAccessKey(keyToDelete)
            })    
            .then(()=>{
                console.log('AWS IAM key rotation complete.');
                this.emit('iamCredentialsUpdated');
            }) 
            .catch((err)=>{
                console.log('Error rotating AWS IAM access credentials ' + err);
                this.emit('Error', 'Rotating AWS IAM access credentials ' + err);
            });
        } else {
            console.log('AWS credentials missing. rotateAccessKey not allowed');
        };
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
                console.log('Error awsAccManClass getNewAccessKey: ' + err, err.stack); // an error occurred
                reject(err);
            } else {
                console.log('new access key object received.');
                resolve(data);
            };
        });
    });
};

function saveNewAccessKey(keyID, keySecret){
    console.log('saving new AWS config...');
    var awsCfgObj = {
        accessKeyId: keyID,
        secretAccessKey: keySecret
    };
    console.log('Writting new awsConfig to ' + creds.filename);
    fs.writeFileSync(creds.filename, JSON.stringify(awsCfgObj));
};

function deleteAccessKey(keyID){
    console.log('Deleting old access key ' + keyID);
    return new Promise((resolve, reject)=>{
        const params = {
            AccessKeyId: keyID
        };
        iam.deleteAccessKey(params, function(err, data) {
            if (err) {
                console.log('Error deletAccessKey ' +  err, err.stack); // an error occurred
                reject(err);
            } else {
                console.log('Old Access Key deleted from AWS.');           // successful response
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
                console.log('Error getAccessKeyUser ' +  err, err.stack); // an error occurred
                reject(err);
            } else {
                //console.log('User for this Key = ' + data);           // successful response
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
                console.log('Error listAccessKeys ' +  err, err.stack); // an error occurred
                reject(err);
            } else {
                //console.log('User for this Key = ' + data);           // successful response
                resolve(data);
            };
        });
    });
};

module.exports = awsAccMan;