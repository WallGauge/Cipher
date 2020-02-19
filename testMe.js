const AccMan =          require('./cipherClass.js').acctManager;
const KeyManger =       require('./cipherClass.js').keyManager;
const Crypto =          require('./cipherClass.js').encryption;
const fs =              require("fs");

const credentialsFile = __dirname + '/awsConfig.json'
var crypto = {};
var maxKeyAgeInDays = 0.1;
testEcnryption()
/*
//testEcnryption();
var accMan = new AccMan(credentialsFile);

console.log('This test will rotate the keys three times.  One at startup, 2nd 30 seconds later, and a 3rd time 30 seconds after that.');
console.log('After the 3rd key rotation and 90 seconds after start, test 4 will test encryption based on the new keys...');

accMan.on('iamReady',()=>{
    console.log('\nTest 1: Rotating credentials on startup...');
    accMan.rotateAccessKey()
    .then(()=>{
        console.log('AWS IAM Credentials have been updated.  Reloading class!!.')
        accMan = new AccMan(credentialsFile);
    })
    .catch((err)=>{
        console.log(err);
    });

});

setTimeout(()=>{
    console.log('\nTest 2: Testing the reload of AccMan credentials worked by renewing key again...');
    accMan.rotateAccessKey()
    .then(()=>{
        console.log('AWS IAM Credentials have been updated.  Reloading class!!.')
        accMan = new AccMan(credentialsFile);
    })
    .catch((err)=>{
        console.log(err);
    });
},30000);

setTimeout(()=>{
    console.log('\nTest 3: Testing the reload of AccMan credentials worked by renewing key again...');
    accMan.rotateAccessKey()
    .then(()=>{
        console.log('AWS IAM Credentials have been updated.  Reloading class!!.')
        accMan = new AccMan(credentialsFile);

        accMan.on('iamReady',()=>{

        });
    })
    .catch((err)=>{
        console.log(err);
    });
},60000);

setTimeout(()=>{
    console.log('\nTest 4: Encryption starting now...');
    testEcnryption();
},90000);
*/

function testEcnryption(){
    var keyID = 'put your key ID here if cmk.json is missing'
    var cmkFilePath = __dirname + '/cmk.json'
    if (fs.existsSync(cmkFilePath)){
        let masterKeyObject = JSON.parse(fs.readFileSync(cmkFilePath)); 
        let keys = Object.keys(masterKeyObject);
        keyID = keys[0];
        console.log('key ID = ' + keyID);
    }

    const keyMan = new KeyManger([keyID], credentialsFile, __dirname + '/cmk.json');
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

    keyMan.on('Error', ((err)=>{
        console.log('We got an error: ' + err);
    }))
};

