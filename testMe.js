const KeyManger =       require('./cipherClass.js').keyManager;
const Crypto =          require('./cipherClass.js').encryption;
const fs =              require("fs");

const testConfigInFilename = './sample_testConfig.json'
const testConfigOutFilename = './sample_testConfig.encrypted'
var testConfigIn = null;

console.log('testMe is setting up keyMan...')
const keyMan = new KeyManger(['b10ec20c-262f-4c80-894c-e8371dd73794','ef1c55a2-1808-450c-824a-62556d46b7b5']);
var crypto = {};

keyMan.on('keyIsReady', (keyObj)=>{
    var keys = Object.keys(keyObj);
    console.log('\nKey ID '+ keys[0] +' is ready for encyption and and the data encyptyion key is ' + keyObj[keys[0]].toString('hex'));
    console.log('This "data key" is never stored localy.  Only an encrypted version is stored localy.');
    console.log('The encrypted data key is decrypted by Amazon Key Mangement services.');


    console.log('\nNow that we have a key lets use it to encrypt something.  Setting up encryption class.');
    crypto = new Crypto(keyObj[keys[0]]);
    var textToEcrypte = "Here are the launch codes (12345) make sure POTUS doesn't see them!"
    console.log('Encrypting ->'+ textToEcrypte +'<-');
    var encryptedTextBuffer = crypto.encrypt(textToEcrypte);
    console.log('Now lets decrypt and see if we get our orignal text:');
    var unencryptedText = crypto.decrypt(encryptedTextBuffer);
    console.dir('Decrypted  ->'+ unencryptedText +'<-');
    testFileEncrypting();
});

keyMan.on('Error', (errDesc, errDetail)=>{
    console.log('Error Desc = ' + errDesc);
    console.log('Error Detail = ' + errDetail);
});

setTimeout(()=>{
    if (keyMan.dataEncryptionKeyObj == {}){
        console.log('Data encryption key not set.  Encryption not possible.');
    } else {
        console.log('\ntestMe:  After 15 seconds the data Encryption Key object follows:');
        console.dir(keyMan.dataEncryptionKeyObj, {depth:null});
    };
},15000);

console.log('testMe is free to do other things...')


function testFileEncrypting(){
    console.log('test File Encryption')
    if (fs.existsSync(testConfigInFilename)){
        testConfigIn = JSON.parse(fs.readFileSync(testConfigInFilename))
        console.log('this is a test object from ' + testConfigInFilename);
        console.dir(testConfigIn, {depth:null});
        
        var encryptedFileBuffer = crypto.encrypt(JSON.stringify(testConfigIn));
        console.log('now lets write this buffer to a file');
        fs.writeFileSync(testConfigOutFilename, encryptedFileBuffer);
        
        console.log('Done. Lets read the encrypted file and decrypt it.');
        var encryptedFileContents = fs.readFileSync(testConfigOutFilename, 'utf8');
        var decryptedFileContents = crypto.decrypt(encryptedFileContents);
        console.log('decryted file contents:');
        console.dir(JSON.parse(decryptedFileContents),{depth:null});
    };
}