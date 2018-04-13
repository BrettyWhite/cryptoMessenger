## CryptoMessenger Android - RSA Encryption For Your App

### Intro

This is meant to be an easy to use asymmetric encryption library. I designed it with instant messengers in mind, but it should be usable for other purposes. 

With that out of the way, the purpose of this is not to be the **best** encryption available. There are plenty of libraries that are studied far more than this, such as the [Signal Library](https://github.com/signalapp/libsignal-service-java), which I urge everyone to look at. With that in mind, this was meant to convince developers who were going to abandon the thought of adding encryption due to complex integrations or lack of subject area knowledge to add it to their app. 

### Encryption

This uses 2048 Bit RSA KeyPairs with:

1. `ECB` as the block mode
2. `PKCS1` as the padding

Keys are held in the [Android Keystore](https://developer.android.com/training/articles/keystore.html). The private key never leaves the user's device.

**WARNING:** If the app is uninstalled or new keys are made, anything encrypted with the previous keys will **NEVER** be able to be restored, and should be considered lost. Please put thought into your system design.

### Installation

Gradle compile line coming soon. 

Maven:

Make sure you have `mavenCentral()` listed as a repository in your project's gradle file:

```ruby
repositories {
    mavenCentral()
}
```
And in your app's build.gradle file:

```ruby
repositories {
    maven { url 'https://dl.bintray.com/brettywhite/cryptomessenger/' }
}
...

dependencies {
    implementation 'com.brettywhite:cryptomessenger:0.0.1'
}

```

### Usage

There are 7 simple public methods in this library:

1. `createKeys(Boolean returnPublicKey)`
2. `getPublicKey()`
3. `encrypt(String plaintext, PublicKey recipientKey)`
4. `decrypt(String cipherText)`
5. `keyExists()`
6. `convertPublicKeyToString(PublicKey pubKey)`
7. `convertStringToPublicKey(String pubKeyString)`

For any use of these public methods, you will need a reference to `KeyManager`:

```java
KeyManager km = new KeyManager(context);
```

The cool thing about this library is it gives you good control of how you handle things. I will give an example use case below:

#### Key Creation

It is good to create your keys when your user registers or logs in for the first time. It is **Extremely** important to check for existing keys first. Additionally, the `createKeys` method contains one parameter that is a boolean. If you pass in true, it sends back a `PublicKey` object. You should then associate this key to the user in your database. You will need it accessible for other users to get this later to send messages back to this user. 

##### Retrieve key after creation:

```java
KeyManager km = new KeyManager(context);
	if (!km.keyExists()) {
		PublicKey userPubKey = km.createKeys(true);
		// store key
	}
```
##### Or without key retrieval:

```java
KeyManager km = new KeyManager(context);
	if (!km.keyExists()) {
		km.createKeys(false);
	}
```

#### Getting the Public Key

If you did not retrieve this key and store it during key creation, fear not. You can simply call:

```java
KeyManager km = new KeyManager(context);
	if (km.keyExists()) {
		PublicKey userPubKey = km.getPublicKey();
		// store key
	}
```
Now you can store your key.

#### Storing the Public Key

Storing your key is easy. The key is easily converted to a string to store in pretty much any database.

```java
String pubKeyString = km.convertPublicKeyToString(userPubKey);
```
### Retrieving Public Keys

To send an encrypted message to another user, you will need their public key. This is why it is suggested to store public keys immediately after registration.

This is more of a design choice for you, the developer. You can pass the user's key back during an inbox response for example. Or you could retrieve it when loading a message thread. It is up to you. You just need the String or PublicKey object. 

If you stored your user's keys as a String, once you are ready to use it, you can call

```java
PublicKey key = convertStringToPublicKey(String pubKeyString)
```
to get the `PublicKey` object needed for encryption.

### Encryption

The encryption method is very straightforward. It takes the message string to be encrypted and the recipient's public key. If you pass in null for the recipient key, it will encrypt with *your* public key. This is useful in systems where you will store a second cipher text in a database as the sender's reference to the message.

```java
String cipherText = keyManager.encrypt(message, recipKey);
```

### Decryption

Decryption is even more straightforward. Any cipher text received needs to be signed by the receiving user's public key. If the decryption fails, it currently will not return anything. 

```java
String plainText = keyManager.decrypt(cipherText);
```

### Missing / Future functionality

1. Signing messages - This will be added soon (to prevent MITM attacks)
2. Unit tests - because why not
3. iOS library - YAY

### Pull Requests

They are welcome, please follow the formatting schemes used.

### ShoutOuts:

[JDog](https://github.com/JRG11G) and
[DDog](https://github.com/danalombardi) :rocket: