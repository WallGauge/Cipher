const _crypto = require ('crypto');

class encryption {
    constructor(encryptionKey){
        this.key = encryptionKey;
    }

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