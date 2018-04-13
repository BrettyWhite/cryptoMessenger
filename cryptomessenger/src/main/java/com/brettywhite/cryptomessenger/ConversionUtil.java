package com.brettywhite.cryptomessenger;

import android.security.keystore.KeyProperties;
import android.util.Base64;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * Created by bmagicdahomie on 4/4/18. <br>
 *
 * Conversion Utilities Used Throughout The Library
 */
public class ConversionUtil {

	private KeyFactory keyFactory;

	 ConversionUtil() {
		try {
			keyFactory = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_RSA);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Convert byte array to String <br>
	 *
	 * @param toEncode - byte array input
	 * @return String
	 */
	public String encode(byte[] toEncode) {
		return Base64.encodeToString(toEncode, Base64.DEFAULT);
	}

	/**
	 * Convert String to byte array <br>
	 *
	 * @param toDecode String input
	 * @return byte array
	 */
	public byte[] decode(String toDecode) {
		return Base64.decode(toDecode, Base64.DEFAULT);
	}

	/**
	 * Turn Char Array into Byte Array
	 *
	 * @param chars - Char Array
	 * @return UTF-8 Safe Byte Array
	 */
	public byte[] toBytes(char[] chars) {
		CharBuffer charBuffer = CharBuffer.wrap(chars);
		ByteBuffer byteBuffer = Charset.forName("UTF-8").encode(charBuffer);
		byte[] bytes = Arrays.copyOfRange(byteBuffer.array(), byteBuffer.position(), byteBuffer.limit());
		Arrays.fill(charBuffer.array(), '\u0000'); // clear the cleartext
		Arrays.fill(byteBuffer.array(), (byte) 0); // clear the ciphertext

		return bytes;
	}

	/**
	 * Turn Byte Array into Char Array
	 *
	 * @param bytes - Byte Array
	 * @return UTF-8 Safe Char Array
	 */
	public char[] toChars(byte[] bytes) {
		Charset charset = Charset.forName("UTF-8");
		ByteBuffer byteBuffer = ByteBuffer.wrap(bytes);
		CharBuffer charBuffer = charset.decode(byteBuffer);
		char[] chars = Arrays.copyOf(charBuffer.array(), charBuffer.limit());
		Arrays.fill(charBuffer.array(), '\u0000'); // clear the cleartext
		Arrays.fill(byteBuffer.array(), (byte) 0); // clear the ciphertext

		return chars;
	}

	/**
	 * This is used mainly to convert public keys to strings
	 * to be stored in something like a database
	 *
	 * @param publicKey - public key to be turned into string
	 * @return String object of Public Key
	 * @throws GeneralSecurityException - surround that thing w/ try catch
	 */
	public String convertPublicKeyToString(PublicKey publicKey) throws GeneralSecurityException {
		X509EncodedKeySpec spec = keyFactory.getKeySpec(publicKey,
				X509EncodedKeySpec.class);
		return encode(spec.getEncoded());
	}

	/**
	 * This is used to convert a string of a stored public
	 * key back to a public key for use
	 *
	 * @param keyString - String to be converted to key
	 * @return PublicKey object
	 * @throws GeneralSecurityException - surround that thing w/ try catch
	 */
	public PublicKey convertStringToPublicKey(String keyString) throws GeneralSecurityException {
		byte[] data = decode(keyString);
		X509EncodedKeySpec spec = new X509EncodedKeySpec(data);
		return keyFactory.generatePublic(spec);
	}
}
