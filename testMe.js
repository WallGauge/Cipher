const AccMan =          require('./cipherClass.js').acctManager;
const KeyManger =       require('./cipherClass.js').keyManager;
const Crypto =          require('./cipherClass.js').encryption;

const credentialsFile = __dirname + '/awsConfig.json'
var crypto = {};
var maxKeyAgeInDays = 0.1;

const accMan = new AccMan(credentialsFile);
accMan.on('iamReady',()=>{
    accMan.getAccessKeyAge()
    .then((keyAgeIndays)=>{
        if(keyAgeIndays < maxKeyAgeInDays){
            console.log('The AWS IAM access key is less than '+ maxKeyAgeInDays +' days old. It should be rotated in ' + (maxKeyAgeInDays - keyAgeIndays).toString() + ' days.')
        } else {
            console.log('Key is '+ keyAgeIndays +' days old, it needs to be rotated. Starting key rotation process...');
            accMan.rotateAccessKey();
        };
    })
    .catch((err)=>{
        console.log('Error in checking if AWS IAM access key needs to be replaced.  Error = ' + err)
    });
});

accMan.on('iamCredentialsUpdated',()=>{
    console.log('AWS IAM Credentials have been updated.  You will now need to restart your applicaitons.')
});

const keyMan = new KeyManger(['ef1c55a2-1808-450c-824a-62556d46b7b5'], credentialsFile);
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
});

