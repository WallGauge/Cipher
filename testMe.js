const AccMan =          require('./cipherClass.js').acctManager;
const KeyManger =       require('./cipherClass.js').keyManager;
const Crypto =          require('./cipherClass.js').encryption;
const fs =              require("fs");

const credentialsFile = __dirname + '/awsConfig.json'
var crypto = {};
var maxKeyAgeInDays = 0.1;
//testEcnryption()

//testEcnryption();
var accMan = new AccMan(credentialsFile);

accMan.on('iamReady',(()=>{
    console.log('Class init okay.');
    console.log('IAM user name =     ' + accMan.userArn);
    console.log('IAM user ID =       ' + accMan.userID);
    console.log('IAM resource Name = ' + accMan.userName)
}));

accMan.on('iamError',((err)=>{
    console.log('there was an error when we tried to init the class:');
    console.log(err.toString());
}));


setTimeout(()=>{createAcct()},5000)


function createAcct(){
    console.log('\nCreate new credentialsFile');

    var createReslut = accMan.createCredentialsFile('', '')
    if(createReslut === true){
        console.log('file created.  Verifying new credentials...');
        accMan.reloadCredentials()
        .then(()=>{
            console.log('New credentials are good!');
            console.log('IAM user name =     ' + accMan.userArn);
            console.log('IAM user ID =       ' + accMan.userID);
            console.log('IAM resource Name = ' + accMan.userName)
        })

        .catch((err)=>{
            console.log('Fail.  New credentials did not work.  Try again');
        })


        // var accManTemp = new AccMan(credentialsFile);

        // accManTemp.on('iamReady',(()=>{
        //     console.log('Class reinit okay.');
        //     console.log('IAM user name =     ' + accManTemp.userArn);
        //     console.log('IAM user ID =       ' + accManTemp.userID);
        //     console.log('IAM resource Name = ' + accManTemp.userName)
        //     accMan = new AccMan(credentialsFile);
        // }));

        // accManTemp.on('iamError',((err)=>{
        //     console.log('there was an error when we tried to reinit class:');
        //     console.log(err.toString());
        //     console.log('there may be somting wrong with the credentials file we just created.')
        // }));
    }
}


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

