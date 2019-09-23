const AWS =             require('aws-sdk');
const fs =              require("fs");
const EventEmitter =    require('events');
var kms = {};

class keyManager extends EventEmitter {
    constructor(newKeyDescription = 'wgGDT1_MasterKey', cmkFilePath = __dirname + '/cmk.json'){
        super();
        this.dataEncryptionKey = null;
        this.masterKeyID = null
        this._cmkFilePath = cmkFilePath;
        this._masterKeyObject = {};
        this._masterKeyParams = {
            Description: newKeyDescription,
            KeyUsage: 'ENCRYPT_DECRYPT',
            Origin: 'AWS_KMS'
        };

        checkForCredentials()
        .then(()=>{
            console.log('keyMangerClass found Amazon Web Service credentials, setting up Key Management Service object...');
            kms = new AWS.KMS({
                accessKeyId: AWS.config.credentials.accessKeyId,            //credentials for your IAM user
                secretAccessKey: AWS.config.credentials.secretAccessKey,    //credentials for your IAM user
                region: 'us-east-1'
            });
            console.log('Looking for Master Key File ' + this._cmkFilePath);
            if (fs.existsSync(this._cmkFilePath)){
                this._masterKeyObject = JSON.parse(fs.readFileSync(this._cmkFilePath));
                this.masterKeyID = this._masterKeyObject.cmkID
                console.log('master key ID '+ this.masterKeyID +' loaded form config file');
                var buf = Buffer.from(this._masterKeyObject.dataKey.data);
                decryptKey(buf)
                .then((key)=>{
                    console.log('Data encryption key is ready.');
                    this.dataEncryptionKey = key;
                    this.emit('keyIsReady', this.dataEncryptionKey);
                })
                .catch((err)=>{
                    console.log('Error key Decryption Error form keyManager');
                    this.emit('Error', 'Key Decryption Error', err);
                })
            } else {
                console.log('Master Key File not found! Creating new Master Key File...');
                getNewMasterKey(this._masterKeyParams)
                .then((keyID)=>{
                    this.masterKeyID = keyID
                    console.log('Amazon Web Servers created a new key ID ' + this.masterKeyID);
                    this._saveItem({cmkID:keyID});
                    return generateDataKey(keyID);
                })
                .then((data)=>{
                    this.dataEncryptionKey = data.Plaintext;
                    this.emit('keyIsReady', this.dataEncryptionKey);
                    console.log('saving encrypted copy of data encryption key...');
                    this._saveItem({dataKey:data.CiphertextBlob});
                })
                .catch((err)=>{
                    console.log('Error Key Decryption Error or Issue creating new Master Key');
                    this.emit('Error', 'Key Decryption Error or Issue creating new Master Key', err);
                });
            };
        })
        .catch((err)=>{
            console.log('ERROR keyMangerClass can not read AWS credentials! Check ~/.aws/credentials file.')
            console.log(err);
            this.emit('Error', 'keyMangerClass can not read AWS credentials! Check ~/.aws/credentials file.', err);
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

function checkForCredentials(){
    console.log('keyMangerClass is checking for AWS Credentials...');
    return new Promise((resolve, reject)=>{
        AWS.config.getCredentials(function(err) {
            if (err){
                reject(err);
            } else {
                resolve();
            };
        });
    });
};

function getNewMasterKey(keyParams){
	return new Promise((resolve, reject)=>{
		kms.createKey(keyParams, function(err, data) {
			if (err){
				console.log('Error getting new Master Key')
				console.log(err); // an error occurred
				reject(err);
			} else {
				resolve(data.KeyMetadata.KeyId);
				console.log('Success we have a new Master Key.')
			};
		});
	});
};

function generateDataKey(keyID) {
	console.log('Asking AWS to generate a data encryption key based on key ID.');
    return new Promise((resolve, reject) => {
		const params = {
            KeyId: keyID, 
            KeySpec: 'AES_256'// Specifies the type of data key to return.
		};

        kms.generateDataKey(params, (err, data) => {
            if (err) {
				console.log('Error calling kms.generteDataKey:');
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

module.exports  = keyManager;