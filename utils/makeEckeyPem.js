const AccMan =          require('../cipherClass.js').acctManager;
const fs =              require("fs");

const awsCredentialsFile = __dirname + '/opt/rGauge/certs/awsCredentials.json' //'/awsConfig.json'
var keyID = '' //put your AWS Key Management Service key ID here if cmk.json is missing
var eckeyPemFile = __dirname + '/eckey.pem'
var eckeyPemEncryptedFile = __dirname + '/eckey.pem.encrypted'
var encContext = ''

console.log('login to AWS to get keyID from user tags...');
var accMan = new AccMan(awsCredentialsFile);
accMan.on('iamReady',(()=>{
    console.log('Class init okay.');
    console.log('IAM user name =     ' + accMan.userArn);
    console.log('IAM user ID =       ' + accMan.userID);
    console.log('IAM resource Name = ' + accMan.userName);
    console.log('IAM user Tags Follow:');
    console.dir(accMan.userTags, {depth:null});
    keyID = accMan.userTags.encKeyID
    encContext = accMan.userTags.gdtAdminApi
    console.log('keyID = ' + keyID);
    console.log('encContext = ' + encContext);

    if(keyID == ''){
        console.error('You must edit this file and give it a keyID or assign it to your IAM user as an encKeyID tag.');
    }  else {
        console.log('\nThis script will encrypt the contents of source file and save it to destination file.')  
        console.log('Caution: If the destination file exist it will be overwritten.\n')
        console.log('     Source File: ' + eckeyPemFile);
        console.log('Destination File: ' + eckeyPemEncryptedFile)
        createFile();
    };
}));

accMan.on('iamError',((err)=>{
    console.log('there was an error when we tried to init the class:');
    console.log(err.toString());
}));

function createFile(){
    console.log('\nStep 1) read source file...');
    let dataToEncrypt = fs.readFileSync(eckeyPemFile);
    console.log('Encryping the folling text from source file:');
    console.log('\n' + dataToEncrypt + '\n');
    accMan.encrypt(dataToEncrypt, {'contextKey':encContext}, keyID)
    .then((encData)=>{
        console.log('Here is the response from the encryption call:');
        console.dir(encData.CiphertextBlob, {depth:null});

        console.log('\nStep 2) Saving the encrypted contents to destination file...');
        fs.writeFileSync(eckeyPemEncryptedFile, encData.CiphertextBlob);

        console.log('\nStep 3) Read the destination file, and decrypt:');
        let dataToDecrypt = fs.readFileSync(eckeyPemEncryptedFile);
        return accMan.decrypt(dataToDecrypt, {'contextKey':encContext})
    })
    .then((data)=>{
        console.log('\n' + data.Plaintext) + '\n';
    })
    .catch((err)=>{
        console.error('Error with encryption testing.', err);
    });

};