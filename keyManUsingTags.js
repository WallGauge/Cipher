const AWS = require('aws-sdk');
const fs = require("fs");
const EventEmitter = require('events');
const AwsAccMan = require("./awsAccManClass");

const logitPrefix = 'cipher.keyManUsingTags | ';
var creds = {};
var kms = {};

class keyManager extends EventEmitter {
    /**
     * This class is used to manage data encryption keys for use with the encryptionClass.js and encrypt small amounts (<4k) of data direclty with AWS KMS cloud.  
     * The data encryption key is encrypted with a Customer Master Key and managed by Amazon Web Services Key Management Service.
     * This class looks for an encrypted “data encryption key” in a local file named cmk.json (default name).  
     * If the cmk.json file is missing the class will use AWS to create a new data encryption key for each customer master key passed.  
     * An encrypted version of the new data encryption key and the customer master key ID will be stored in the cmk.json file.  
     * The CMK ID is used by AWS to decrypt the data encryption key and it is available in the this.dataEncryptionKey property. 
     * The this.dataEncryptionKey key should never be stored or saved in the file system!
     * 
     * Emits:
     *      this.emit('keyIsReady', this.dataEncryptionKeyObj);  When a data encryption key has been decrypted and ready.
     *      this.emit('Error', 'Key Decryption Error', err);  Emits various errors in this format.
     * 
     * @param {string} tagID This is the AWS IAM user tag key name that holds the master key ID  
     * @param {string} credentialsFile File location of the AWS IMA credentials in JSON format 
     * @param {string} cmkFilePath This is an optional file path and name of the location to store the CMK ID and encryted data key
     * @param {string} awsRegion This is your Amazon region (location of your AWS KMS account)
     */
    constructor(tagID = 'encKeyID', credentialsFile = __dirname + '/awsConfig.json', cmkFilePath = __dirname + '/cmk.json', awsRegion = 'us-east-1') {
        super();
        this.dataEncryptionKeyObj = {};
        this._tagID = tagID;
        this._credentialsFile = credentialsFile;
        this._cmkFilePath = cmkFilePath;
        this._region = awsRegion;
        this._cmkId = null;
        this._masterKeyObject = {};

        logit('Setting up awsAccMan aka keyManagerClass... credentials location = ' + this._credentialsFile);
        this.awsAccMan = new AwsAccMan(this._credentialsFile);

        this.awsAccMan.on('iamReady', () => {
            this._cmkId = this.awsAccMan.userTags[this._tagID];
            if (this._cmkId != null && this._cmkId != undefined) {
                logit('We have a key ID from the ' + this._tagID + ' AWS IAM Tag.')
                this._masterKeyParams = {
                    Description: 'GDT',
                    KeyUsage: 'ENCRYPT_DECRYPT',
                    Origin: 'AWS_KMS'
                };
                creds = new AWS.FileSystemCredentials(this._credentialsFile);  //https://docs.aws.amazon.com/AWSJavaScriptSDK/latest/AWS/FileSystemCredentials.html
                checkForCredentials(this._credentialsFile)
                    .then(() => {
                        logit('Setting up AWS KMS...');
                        kms = new AWS.KMS({
                            accessKeyId: creds.accessKeyId,            //credentials for your IAM user
                            secretAccessKey: creds.secretAccessKey,    //credentials for your IAM user
                            region: this._region
                        });
                        if (fs.existsSync(this._cmkFilePath)) {
                            this._masterKeyObject = JSON.parse(fs.readFileSync(this._cmkFilePath));
                            var cmkList = Object.keys(this._masterKeyObject);
                            cmkList.forEach((keyIdFromFile) => {
                                var buf = Buffer.from(this._masterKeyObject[keyIdFromFile]);
                                decryptKey(buf)
                                    .then((key) => {
                                        this.dataEncryptionKeyObj[keyIdFromFile] = key;
                                        this.emit('keyIsReady', { [keyIdFromFile]: key });
                                    })
                                    .catch((err) => {
                                        console.error('Error key Decryption Error form keyManager for cmkID = ' + keyIdFromFile);
                                        this.emit('Error', 'Key Decryption Error for keyID = ' + keyIdFromFile, err);
                                    })
                            });
                            if (cmkList.indexOf(this._cmkId) == -1) {
                                logit('CMK ID ' + this._cmkId + ', missing, creating a new one.');
                                generateDataKey(this._cmkId)
                                    .then((data) => {
                                        this.dataEncryptionKeyObj[this._cmkId] = data.Plaintext;
                                        logit('saving encrypted copy of data encryption key...');
                                        this._saveItem({ [this._cmkId]: data.CiphertextBlob });
                                        this.emit('keyIsReady', { [this._cmkId]: data.Plaintext });
                                    })
                                    .catch((err) => {
                                        console.error('Error Key Decryption Error or Issue creating new data encryption Key for key ID ' + this._cmkId);
                                        this.emit('Error', 'Key Decryption Error or Issue creating new data encryption Key for key ID ' + this._cmkId, err);
                                    });
                            };
                        } else {
                            logit('Data encryption Key File not found! Creating new File...');
                            generateDataKey(this._cmkId)
                                .then((data) => {
                                    this.dataEncryptionKeyObj[this._cmkId] = data.Plaintext;
                                    logit('saving encrypted copy of data encryption key...');
                                    this._saveItem({ [this._cmkId]: data.CiphertextBlob });
                                    this.emit('keyIsReady', { [this._cmkId]: data.Plaintext });
                                })
                                .catch((err) => {
                                    console.error('Error Key Decryption Error or Issue creating new data encryption Key for key ID ' + this._cmkId);
                                    this.emit('Error', 'Key Decryption Error or Issue creating new data encryption Key for key ID ' + this._cmkId, err);
                                });
                        };
                    })
                    .catch((err) => {
                        console.error('Error: keyMangerClass error while checking for AWS IAM credentials.', err);
                    });
            } else {
                logit('Error: Key ID missing.  ASW IAM Tag named ' + this._tagID + ' not found.')
                throw (new Error('Error: Key ID missing.  ASW IAM Tag named ' + this._tagID + ' not found.'));
            };
        });
    };

    /** Saves custom config items to the config file located in _masterKeyID Path 
     * Item to be saved should be in key:value format.  For example to seave the IP address of a device call this method with
     * saveItem({webBoxIP:'10.10.10.12});
     * @param {Object} itemsToSaveAsObject 
     */
    _saveItem(itemsToSaveAsObject) {
        var itemList = Object.keys(itemsToSaveAsObject);
        itemList.forEach((keyName) => {
            this._masterKeyObject[keyName] = itemsToSaveAsObject[keyName];
        })
        fs.writeFileSync(this._cmkFilePath, JSON.stringify(this._masterKeyObject));
        this._reloadConfig();
    };

    _reloadConfig() {
        logit('config reloading...');
        this._masterKeyObject = {};
        if (fs.existsSync(this._cmkFilePath)) {
            this._masterKeyObject = JSON.parse(fs.readFileSync(this._cmkFilePath));
        };
    };
};

function checkForCredentials(fileName) {
    return new Promise((resolve, reject) => {
        fs.access(fileName, fs.constants.R_OK, (err) => {
            if (err) {
                reject(err);
            } else {
                resolve();
            };
        });
    });
};

function generateDataKey(keyID) {
    logit('Asking AWS to generate a data encryption key for CMK ID: ' + keyID);
    return new Promise((resolve, reject) => {
        const params = {
            KeyId: keyID,
            KeySpec: 'AES_256'// Specifies the type of data key to return.
        };

        kms.generateDataKey(params, (err, data) => {
            if (err) {
                console.error('Error calling kms.generateDataKey:', err);
                reject(err);
            } else {
                resolve(data);
            };
        });
    });
};

function decryptKey(encryptedKeyBuffer) {
    return new Promise((resolve, reject) => {
        const params = {
            CiphertextBlob: encryptedKeyBuffer
        };

        kms.decrypt(params, (err, data) => {
            if (err) {
                console.error('Error calling kms.decrypt:', err);
                reject(err);
            } else {
                resolve(data.Plaintext);
            };
        });
    });
};

function logit(txt = '') {
    console.debug(logitPrefix + txt)
};

module.exports = keyManager;