package com.tasosmartidis.tutorial.encryption.encryptor;

import com.tasosmartidis.tutorial.encryption.domain.EncryptorProperties;
import com.tasosmartidis.tutorial.encryption.exception.DecryptionException;
import com.tasosmartidis.tutorial.encryption.exception.EncryptionException;
import com.tasosmartidis.tutorial.encryption.exception.EncryptorInitializationException;
import com.tasosmartidis.tutorial.encryption.exception.UnauthorizedForDecryptionException;
import org.apache.commons.codec.binary.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.*;

public class BaseAsymmetricEncryptor {
	private final KeyPairGenerator keyPairGenerator;
	private final KeyPair keyPair;
	private final Cipher cipher;
	private final EncryptorProperties encryptorProperties;

	protected BaseAsymmetricEncryptor(EncryptorProperties encryptorProperties) {
		this.encryptorProperties = encryptorProperties;
		this.keyPairGenerator = generateKeyPair();
		this.keyPairGenerator.initialize(this.encryptorProperties.getKeyLength());
		this.keyPair = this.keyPairGenerator.generateKeyPair();
		this.cipher = createCipher(encryptorProperties);
	}

	protected PrivateKey getPrivateKey() {
		return this.keyPair.getPrivate();
	}

	public PublicKey getPublicKey() {
		return this.keyPair.getPublic();
	}

	protected String encryptText(String textToEncrypt, Key key) {
		try {
			this.cipher.init(Cipher.ENCRYPT_MODE, key);
			return Base64.encodeBase64String(cipher.doFinal(textToEncrypt.getBytes(StandardCharsets.UTF_8)));
		} catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException ex) {
			throw new EncryptionException("Encryption of message failed", ex);
		}
	}

	protected String decryptText(String textToDecrypt, Key key) {
		try {
			this.cipher.init(Cipher.DECRYPT_MODE, key);
			return new String(cipher.doFinal(Base64.decodeBase64(textToDecrypt)), StandardCharsets.UTF_8);
		}catch (InvalidKeyException | BadPaddingException ex){
			throw new UnauthorizedForDecryptionException("Not authorized to decrypt message", ex);
		} catch (IllegalBlockSizeException ex) {
			throw new DecryptionException("Decryption of message failed", ex);
		}
	}

	private Cipher createCipher(EncryptorProperties encryptorProperties) {
		try {
			return Cipher.getInstance(encryptorProperties.getAsymmetricAlgorithm());
		} catch (NoSuchAlgorithmException | NoSuchPaddingException ex) {
			throw new EncryptorInitializationException("Creation of cipher failed", ex);
		}
	}

	private KeyPairGenerator generateKeyPair() {

		try {
			return KeyPairGenerator.getInstance(this.encryptorProperties.getAsymmetricAlgorithm());
		} catch (NoSuchAlgorithmException ex) {
			throw new EncryptorInitializationException("Creation of encryption keypair failed", ex);
		}
	}

}
