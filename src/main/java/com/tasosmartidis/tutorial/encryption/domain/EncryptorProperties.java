package com.tasosmartidis.tutorial.encryption.domain;

import lombok.AllArgsConstructor;


@AllArgsConstructor
public class EncryptorProperties {
	private final AsymmetricAlgorithm asymmetricAlgorithm;
	private final int keyLength;

	public String getAsymmetricAlgorithm() {
		return asymmetricAlgorithm.toString();
	}

	public int getKeyLength() {
		return keyLength;
	}
}
