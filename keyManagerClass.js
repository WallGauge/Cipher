const AWS =             require('aws-sdk');
const fs =              require("fs");
const EventEmitter =    require('events');

var creds = {};
var kms = {};

/**
 * This class is used to manage data encryption keys.  The key is encrypted with a Customer Master Key and managed by Amazon Web Services Key Management Service.
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
 * @param {string} cmkIDs This text string array must have a list of customer master keys to use for encryption 
 * @param {string} CredentialsFile File location of the AWS IMA credentials in JSON format 
 * @param {string} cmkFilePath This is an optional file path and name of the location to store the CMK ID and encryted key
 * @param {string} awsRegion This is your Amazon region (location of your AWS KMS account)
 */
class keyManager extends EventEmitter {
    constructor(cmkIDs = ['',''], CredentialsFile =  __dirname + '/awsConfig.json', cmkFilePath = __dirname + '/cmk.json',  awsRegion = 'us-east-1'){
        super();
        this.dataEncryptionKeyObj = {};
        this._credentialsFile = CredentialsFile
        this._cmkIdArray = cmkIDs;
        this._region = awsRegion;
        this._cmkFilePath = cmkFilePath;
        this._masterKeyObject = {};
        this._masterKeyParams = {
            Description: 'GDT',
            KeyUsage: 'ENCRYPT_DECRYPT',
            Origin: 'AWS_KMS'
        };
        creds = new AWS.FileSystemCredentials(this._credentialsFile);  //https://docs.aws.amazon.com/AWSJavaScriptSDK/latest/AWS/FileSystemCredentials.html
        checkForCredentials(this._credentialsFile)
        .then(()=>{
            kms = new AWS.KMS({
                accessKeyId: creds.accessKeyId,            //credentials for your IAM user
                secretAccessKey: creds.secretAccessKey,    //credentials for your IAM user
                region: this._region
            });
            if (fs.existsSync(this._cmkFilePath)){
                this._masterKeyObject = JSON.parse(fs.readFileSync(this._cmkFilePath));
                var cmkList = Object.keys(this._masterKeyObject);
                cmkList.forEach((keyIdFromFile)=>{
                    var buf = Buffer.from(this._masterKeyObject[keyIdFromFile]);
                    decryptKey(buf)
                    .then((key)=>{
                        console.log('Data encryption key is ready for cmkID = ' + keyIdFromFile);
                        this.dataEncryptionKeyObj[keyIdFromFile]=key;
                        this.emit('keyIsReady', {[keyIdFromFile]:key});
                    })
                    .catch((err)=>{
                        console.log('Error key Decryption Error form keyManager for cmkID = ' + keyIdFromFile);
                        this.emit('Error', 'Key Decryption Error for keyID = ' + keyIdFromFile, err);
                    })
                });

                this._cmkIdArray.forEach((val)=>{
                    if(cmkList.indexOf(val) == -1){
                        console.log('CMK ID ' + val + ', missing.');
                        generateDataKey(val)
                        .then((data)=>{
                            this.dataEncryptionKeyObj[val] = data.Plaintext;
                            console.log('saving encrypted copy of data encryption key...');
                            this._saveItem({[val]:data.CiphertextBlob});
                            this.emit('keyIsReady', {[val]:data.Plaintext});
                        })
                        .catch((err)=>{
                            console.log('Error Key Decryption Error or Issue creating new data encryption Key for key ID ' + val);
                            this.emit('Error', 'Key Decryption Error or Issue creating new data encryption Key for key ID ' + val, err);
                        });
                    };
                });

            } else {                
                console.log('Data encryption Key File not found! Creating new File...');
                this._cmkIdArray.forEach((val)=>{
                    generateDataKey(val)
                    .then((data)=>{
                        this.dataEncryptionKeyObj[val] = data.Plaintext;
                        console.log('saving encrypted copy of data encryption key...');
                        this._saveItem({[val]:data.CiphertextBlob});
                        this.emit('keyIsReady', {[val]:data.Plaintext});
                    })
                    .catch((err)=>{
                        console.log('Error Key Decryption Error or Issue creating new data encryption Key for key ID ' + val);
                        this.emit('Error', 'Key Decryption Error or Issue creating new data encryption Key for key ID ' + val, err);
                    });
                });
            };
        })
        .catch((err)=>{
            console.log('Error: keyMangerClass error checking AWS credentials: ' + err);
            console.log('Check credentilas file: ' + this._credentialsFile);
            this.emit('Error', 'keyMangerClass can not read AWS credentials! Check ' + this._credentialsFile + ' err: ' + err);
        });
        
    };

    /** Saves custom config items to the config file located in _masterKeyID Path 
     * Item to be saved should be in key:value format.  For example to seave the IP address of a device call this method with
     * saveItem({webBoxIP:'10.10.10.12});
     * @param {Object} itemsToSaveAsObject 
     */
    _saveItem(itemsToSaveAsObject){
        //console.log('saveItem called with:');
        //console.log(itemsToSaveAsObject);
    
        var itemList = Object.keys(itemsToSaveAsObject);
        itemList.forEach((keyName)=>{
            this._masterKeyObject[keyName] = itemsToSaveAsObject[keyName];
        })
        //console.log('Writting file to ' + this._cmkFilePath);
        fs.writeFileSync(this._cmkFilePath, JSON.stringify(this._masterKeyObject));
        this._reloadConfig();
    };

    _reloadConfig(){
        console.log('config reloading...');
        this._masterKeyObject = {};
        if (fs.existsSync(this._cmkFilePath)){
            this._masterKeyObject = JSON.parse(fs.readFileSync(this._cmkFilePath));
        };
    };
};

function checkForCredentials(fileName){
    return new Promise((resolve, reject)=>{
        fs.exists(fileName,(exists)=>{
            if(exists == true){
                fs.access(fileName, fs.constants.R_OK, (err)=>{
                    if(err){
                        console.log('Error: keyManagerClass can not access credentials file ' + fileName);
                        reject('Error: keyMangerClass can not access credentials file ' + fileName);
                    } else {
                        resolve();
                    };
                });
            } else {
                console.log('Error: keyMangerClass can not find credentials file ' + fileName);
                reject('Error: keyMangerClass can not find credentials file ' + fileName);
            };
        });
    });
};

function generateDataKey(keyID) {
	console.log('Asking AWS to generate a data encryption key for CMK ID: ' + keyID);
    return new Promise((resolve, reject) => {
		const params = {
            KeyId: keyID, 
            KeySpec: 'AES_256'// Specifies the type of data key to return.
		};

        kms.generateDataKey(params, (err, data) => {
            if (err) {
				console.log('Error calling kms.generateDataKey:');
				console.log(err);
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
				console.log('Error calling kms.decrypt:');
				console.log(err);
                reject(err);
            } else {
                resolve(data.Plaintext);
            };
        });
    });
};

module.exports = keyManager;