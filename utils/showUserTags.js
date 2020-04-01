const AccMan =          require('../cipherClass.js').acctManager;

const credentialsFile = __dirname + '/awsConfig.json'

var accMan = new AccMan(credentialsFile);

accMan.on('iamReady',(()=>{
    console.log('Class init okay.');
    console.log('IAM user name =     ' + accMan.userArn);
    console.log('IAM user ID =       ' + accMan.userID);
    console.log('IAM resource Name = ' + accMan.userName);
    console.log('IAM user Tags Follow:');
    console.dir(accMan.userTags, {depth:null});
}));

accMan.on('iamError',((err)=>{
    console.log('there was an error when we tried to init the class:');
    console.log(err.toString());
}));


