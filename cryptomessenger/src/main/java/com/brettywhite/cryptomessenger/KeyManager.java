package com.brettywhite.cryptomessenger;

import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Enumeration;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import static android.security.keystore.KeyProperties.KEY_ALGORITHM_RSA;

/**
 * Created by bmagicdahomie on 4/3/18. <br>
 *
 * Public Methods: <br>
 *
 * <li> {@link KeyManager#createKeys(Boolean returnPublicKey)} </li>
 * <li> {@link KeyManager#encrypt(String, PublicKey)} </li>
 * <li> {@link KeyManager#decrypt(String)} </li>
 * <li> {@link KeyManager#keyExists()} </li>
 * <li> {@link KeyManager#convertStringToPublicKey(String)} </li>
 * <li> {@link KeyManager#convertPublicKeyToString(PublicKey)} </li>
 * <li> {@link KeyManager#getPublicKey()}  </li><br><br>
 *
 * To retrieve public keys from your API for use in the {@link KeyManager#convertStringToPublicKey(String)} method,
 * it is recommended that you send them back in a way that reduces networking calls. For example, in a messenger
 * you may want to return the recip's key when retrieving the thread, or when loading your inbox. I do not provide
 * a method for that, because it is smarter to send them along with your other data. <br><br>
 *
 * Stores generated keys in the Android Keystore https://developer.android.com/training/articles/keystore.html <br><br>
 *
 * Shout Outs: <br>
 * Some code for lib used or inspired from https://developer.android.com/samples/BasicAndroidKeyStore/index.html <br>
 * And https://github.com/Mauin/RxFingerprint
 */
public class KeyManager {

	// Constants
	private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
	private static final String DEFAULT_KEY_NAME = "securefam_default";
	private static final int DEFAULT_KEY_SIZE = 2048;

	// Class Vars
	private ConversionUtil conversionUtil;
	private KeyStore keyStore;
	private KeyFactory keyFactory;

	public KeyManager(Context context) {
		conversionUtil = new ConversionUtil();
		try {
			keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
			keyStore.load(null);
			keyFactory = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_RSA);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * Creates a public and private key and stores it using the Android Key Store, so that only
	 * this application will be able to access the keys.<br>
	 *
	 * It is smart to check to see if keys have been made previously, as they will be overwritten if this is called
	 * a second time. Use the keyExists() method to do that check.<br>
	 *
	 * Cryptography - Uses RSA 2048 bit keys, with Block Mode ECB and PKCS1 Padding <br>
	 *
	 * This method does not return anything :(
	 */
	@SuppressWarnings("WeakerAccess")
	public PublicKey createKeys(Boolean returnPublicKey)  {
		KeyPairGenerator generator;
		try {
			generator = KeyPairGenerator.getInstance(KEY_ALGORITHM_RSA, ANDROID_KEY_STORE);
			generator.initialize(new KeyGenParameterSpec.Builder(
					DEFAULT_KEY_NAME,
					KeyProperties.PURPOSE_DECRYPT | KeyProperties.PURPOSE_ENCRYPT)
					.setBlockModes(KeyProperties.BLOCK_MODE_ECB)
					.setKeySize(DEFAULT_KEY_SIZE)
					.setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
					.build()
			);
			generator.generateKeyPair();

			if (returnPublicKey){
				return getPubKey(keyFactory,keyStore);
			}

		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * Encrypt using asymmetric cryptography (RSA)<br>
	 * If you have not done so, you must call createKeys() first.<br>
	 * It is also smart to check of keys have been made previously with the keyExists() call<br>
	 *
	 * @param plainText - Text to be encrypted by your public key
	 * @param recipKey - Public key of person you are sending the message to. If null, it will encrypt with your own public key
	 * @return cipherText - Encrypted text
	 */
	@SuppressWarnings("WeakerAccess")
	public String encrypt(String plainText, PublicKey recipKey) {
		try {
			if (recipKey == null){
				recipKey = getPubKey(keyFactory,keyStore);
			}
			Cipher cipher = getCipherForEncryption(recipKey);
			byte[] encryptedBytes = cipher.doFinal(conversionUtil.toBytes(plainText.toCharArray()));
			return conversionUtil.encode(encryptedBytes);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * Decrypt using asymmetric cryptography (RSA)
	 * This method is used to decrypt cipher text that was encrypted with <strong>your</strong> public key
	 *
	 * @param cipherText - Pass in the cipher text created by calling the encoded() method
	 * @return plainText - The decrypted string
	 */
	@SuppressWarnings("WeakerAccess")
	public String decrypt(String cipherText)  {
		try {
			Cipher cipher = getCipherForDecryption();
			byte[] bytes = cipher.doFinal(conversionUtil.decode(cipherText));
			return String.valueOf(conversionUtil.toChars(bytes));
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * Check the KeyStore to see if we've created a keypair before
	 * It is important to check so we don't overwrite existing keys
	 *
	 * @return boolean - If the key exists. If it does not, call createKeys()
	 */
	@SuppressWarnings("WeakerAccess")
	public boolean keyExists()  {
		try {
			Enumeration<String> aliases = keyStore.aliases();
			while (aliases.hasMoreElements()) {
				if (DEFAULT_KEY_NAME.equals(aliases.nextElement())) {
					return true;
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return false;
	}

	/**
	 * Convert public key string to PublicKey
	 *
	 * @param keyString - string of key
	 * @return PublicKey
	 */
	@SuppressWarnings("WeakerAccess")
	public PublicKey convertStringToPublicKey(String keyString){
		try {
			return conversionUtil.convertStringToPublicKey(keyString);
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * Convert PublicKey object to String
	 *
	 * @param pubKey - the user's public key object
	 * @return String - the string of the key for storage
	 */
	@SuppressWarnings("WeakerAccess")
	public String convertPublicKeyToString(PublicKey pubKey){
		try {
			return conversionUtil.convertPublicKeyToString(pubKey);
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * Get this User's public key. A key pair should have been generated first <br>
	 * <strong>Always check for an existing keypair using {@link KeyManager#keyExists()} before calling {@link KeyManager#createKeys(Boolean returnPublicKey)}  </strong>
	 *
	 * @return this user's PublicKey
	 */
	public PublicKey getPublicKey(){
		try {
			return getPubKey(keyFactory, keyStore);
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}
		return null;
	}

	private Cipher getCipherForEncryption(PublicKey publicKey) throws GeneralSecurityException {
		Cipher cipher = createCipher();
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		return cipher;
	}

	private Cipher getCipherForDecryption() throws GeneralSecurityException {
		Cipher cipher = createCipher();
		cipher.init(Cipher.DECRYPT_MODE, getPrivateKey(keyStore, DEFAULT_KEY_NAME));
		return cipher;
	}

	private Cipher createCipher() throws NoSuchPaddingException, NoSuchAlgorithmException {
		return Cipher.getInstance(KeyProperties.KEY_ALGORITHM_RSA + "/"
				+ KeyProperties.BLOCK_MODE_ECB + "/"
				+ KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1);
	}

	private PublicKey getPubKey(KeyFactory keyFactory, KeyStore keyStore) throws GeneralSecurityException {
		PublicKey publicKey = keyStore.getCertificate(DEFAULT_KEY_NAME).getPublicKey();
		KeySpec spec = new X509EncodedKeySpec(publicKey.getEncoded());
		return keyFactory.generatePublic(spec);
	}

	private PrivateKey getPrivateKey(KeyStore keyStore, String keyAlias) throws GeneralSecurityException {
		return (PrivateKey) keyStore.getKey(keyAlias, null);
	}
}
