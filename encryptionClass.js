const _crypto = require ('crypto');

class encryption {
    /**
     * This class uses the Node.js crypto object to encrypt lage files.  
     * The encrypton is based on the encrption key passed to the constructor.  
     * The encryption key should be generated and encrypted with a 3rd party encryption service like Amazon Web Services KMS
     * @param {string} encryptionKey a key that will be used to encrypt and decrypt data
    */
    constructor(encryptionKey){
        this.key = encryptionKey;
    }

    /**
     * Encrypts data base on the key passed to this class.  Ueses a AES-256-GCM cipher
     * @param {String} text = text to encrypt
     * @returns{buffer} 
     */
    encrypt(text) {
        // random initialization vector
        const iv = _crypto.randomBytes(16);
        // random salt
        const salt = _crypto.randomBytes(64);

        const key = _crypto.pbkdf2Sync(this.key, salt, 2145, 32, 'sha512');
        const cipher = _crypto.createCipheriv('aes-256-gcm', key, iv);
        const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
        const tag = cipher.getAuthTag();

        return Buffer.concat([salt, iv, tag, encrypted]).toString('base64');
    };

    /**
     * Decrypts a buffer from the above encrypt command. 
     * @param {buffer} encData 
     * @returns {string} decrypted data
     */
    decrypt(encData){
        const bData = Buffer.from(encData, 'base64');
        // convert data to buffers
        const salt = bData.slice(0, 64);
        const iv = bData.slice(64, 80);
        const tag = bData.slice(80, 96);
        const text = bData.slice(96);

        // derive key using; 32 byte key length
        const key = _crypto.pbkdf2Sync(this.key, salt , 2145, 32, 'sha512');
        // AES 256 GCM Mode
        const decipher = _crypto.createDecipheriv('aes-256-gcm', key, iv);
        decipher.setAuthTag(tag);
        // encrypt the given text
        const decrypted = decipher.update(text, 'binary', 'utf8') + decipher.final('utf8');
        return decrypted;
    };
};

module.exports = encryption;