package com.tasosmartidis.tutorial.encryption.encryptor;

import com.tasosmartidis.tutorial.encryption.domain.AsymmetricAlgorithm;
import com.tasosmartidis.tutorial.encryption.domain.EncryptedMessage;
import com.tasosmartidis.tutorial.encryption.domain.EncryptorProperties;
import org.bouncycastle.jcajce.provider.digest.SHA3;
import org.bouncycastle.util.encoders.Hex;

import java.security.PublicKey;

public class RsaEncryptor extends BaseAsymmetricEncryptor {
	private static final int KEY_LENGTH = 2048;

	public RsaEncryptor() {
		super(new EncryptorProperties(AsymmetricAlgorithm.RSA, KEY_LENGTH));
	}

	public String encryptMessageForPublicKeyOwner(String message, PublicKey key) {
		 return super.encryptText(message, key);
	}

	public String encryptMessageWithPrivateKey(String message) {
		return super.encryptText(message, super.getPrivateKey());
	}

	public String decryptReceivedMessage(EncryptedMessage message) {
		return super.decryptText(message.getEncryptedMessagePayload(), super.getPrivateKey());
	}

	public String decryptMessageFromOwnerOfPublicKey(String message, PublicKey publicKey) {
		return super.decryptText(message, publicKey);
	}

	public String hashMessage(String message) {
		SHA3.DigestSHA3 digestSHA3 = new SHA3.Digest512();
		byte[] messageDigest = digestSHA3.digest(message.getBytes());
		return Hex.toHexString(messageDigest);
	}
}
