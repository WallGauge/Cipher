const KeyManger =       require('../cipherClass.js').keyManager;
const fs =              require("fs");

const awsCredentialsFile = __dirname + '/awsConfig.json'
var keyID = 'ef1c55a2-1808-450c-824a-62556d46b7b5' //put your AWS Key Management Service key ID here if cmk.json is missing
var eckeyPemFile = __dirname + '/eckey.pem'
var eckeyPemEncryptedFile = __dirname + '/eckey.pem.encrypted'

if(keyID == ''){
    console.error('You must edit this file and give it a keyID');
}  else {
    console.log('\nThis script will encrypt the contents of source file and save it to destination file.')  
    console.log('Caution: If the destination file exist it will be overwritten.\n')
    console.log('     Source File: ' + eckeyPemFile);
    console.log('Destination File: ' + eckeyPemEncryptedFile)
    createFile();
}

function createFile(){
    console.log('\nStep 1) read source file...');
    const keyMan = new KeyManger([keyID], awsCredentialsFile, __dirname + '/cmk.json');
    keyMan.on('keyIsReady', (keyObj)=>{
        let dataToEncrypt = fs.readFileSync(eckeyPemFile);
        console.log('Encryping the folling text from source file:');
        console.log('\n' + dataToEncrypt + '\n');
        keyMan.encrypt(dataToEncrypt)
        .then((encData)=>{
            console.log('Here is the response from the encryption call:');
            console.dir(encData.CiphertextBlob, {depth:null});

            console.log('\nStep 2) Saving the encrypted contents to destination file...');
            fs.writeFileSync(eckeyPemEncryptedFile, encData.CiphertextBlob)

            console.log('\nStep 3) Read the destination file, and decrypt:')
            let dataToDecrypt = fs.readFileSync(eckeyPemEncryptedFile);
            return keyMan.decrypt(dataToDecrypt)
        })
        .then((data)=>{
            console.log('\n' + data.Plaintext) + '\n';
        })
        .catch((err)=>{
            console.error('Error with encryption testing.', err);
        });
    });

};