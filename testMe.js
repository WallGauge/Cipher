const KeyManger = require('./cipherClass.js').keyManager;
const Crypto = require('./cipherClass.js').encryption;

console.log('testMe is setting up keyMan...')
const keyMan = new KeyManger('testMe.js requested key for testing');
var crypto = {};

keyMan.on('keyIsReady', (key)=>{
    console.log('\nThe key I can use for encrypting data is ' + key.toString('hex'));
    console.log('This "data key" is never stored localy.  Only an encrypted version is stored localy.');
    console.log('The encrypted data key is decrypted by Amazon Key Mangement services.');


    console.log('\nNow that we have a key lets use it to encrypt something.  Setting up encryption class.');
    crypto = new Crypto(key);
    var textToEcrypte = "Here are the launch codes (12345) make sure POTUS doesn't see them!"
    console.log('Encrypting ->'+ textToEcrypte +'<-');
    var encryptedTextBuffer = crypto.encrypt(textToEcrypte);
    console.log('Now lets decrypt and see if we get our orignal text:');
    var unencryptedText = crypto.decrypt(encryptedTextBuffer);
    console.dir('Decrypted  ->'+ unencryptedText +'<-');
});

keyMan.on('Error', (errDesc, errDetail)=>{
    console.log('Error Desc = ' + errDesc);
    console.log('Error Detail = ' + errDetail);
});

setTimeout(()=>{
    if (keyMan.dataEncryptionKey == null){
        console.log('Data encryption key not set.  Encryption not possible.');
    } else {
        console.log('\ntestMe:  After 90 seconds the data Encryption Key = ' + keyMan.dataEncryptionKey.toString('hex'));
    };
},90000);

console.log('testMe is free to do other things...')