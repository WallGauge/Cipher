# Cipher
This class is used to manage encryption keys and encrypt data using those keys.  Keys are managed by Amazon Web Services Key Management Service.  Encryption is based on the native Node.js crypto library utilizing Galois/Counter mode AES 256 GCM encryption. 

The main cipher class calls three subclasses, you can reference them individually: 
* const KMS = require(‘cipher’).keyManager
* const Encryption = require(‘cipher’).encryption
* const AccMan = require('cipher').acctManager;

See testMe.js for examples on how initialize each class and make calls.

## keyManager class
The keyManager subclass is based on the Amazon Web Services SDK and logs-in with the credentials in the file passed during construction.  The credentials should be based on an IAM access key ID and secret, that has the ability to access Amazons KMS service. For more information see https://docs.aws.amazon.com/AWSJavaScriptSDK/latest/AWS/FileSystemCredentials.html.

The primary goal of the keyManager class is to securely manage encryption keys.  When keyManager is constructed it is passed an array of cmk IDs and looks for an encrypted “encryption key” in a local file named cmk.json for each cmk ID.  If the cmk.json file is missing the keyManager class will use AWS to create new encryption keys.  An encrypted version of the new key and the customer master key ID will be stored in the cmk.json file.  An unencrypted version of the new encryption key is available as a property of the keyManager class.  This key should never be stored or saved in the file system!  If you store or make an unencrypted version of the encryption key available you have defeated the purpose of AWS-KMS service. 
## encryption class
The encryption class is independent of Amazon Web Services. It is based on the crypto library built into Node.js.  You construct the class by passing it an encryption key (the unencrypted key from the keyManager class).  Once the class is constructed you can then call the encrypt and decrypt methods.  These methods will encrypt the data based on an aes-256-gcm cipher with random salt and Initialization Vectors. 
## account management class 
This class is used to manage and rotate the AWS IAM id login credentials.  This should be done every 90 days to follows AWS best practice. The credentials should be based on an IAM access key ID and secret, that has the ability to access Amazons KMS service. For more information see https://docs.aws.amazon.com/AWSJavaScriptSDK/latest/AWS/FileSystemCredentials.html.
## Why is this secure?
Well it may not be.  It is up to the calling node.js application(s) to correctly use this class.  Since the encryption key is never stored or shared with anyone unless it is encrypted, hackers will find it very difficult to decrypt your data.  Even if they have both the encrypted key and the encrypted data it will be very difficult to decrypt.  However, if you make an unencrypted version of the encryption key available then a hacker could easily decrypt your data.  Similarly if a hacker has access to your AWS IAM ID and Secret, CMK ID, and your encrypted key they could decrypt your data.  You need to consider these risks when you architect your application.