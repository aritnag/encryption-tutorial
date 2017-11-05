package com.tasosmartidis.tutorial.encryption.domain;

import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;

@AllArgsConstructor
@Getter
@EqualsAndHashCode
public class EncryptedMessage {
	private String encryptedMessagePayload;
    private String senderId;
    private String encryptedSenderId;
    private String messageDigest;

    // FOR DEMO PURPOSES ONLY!
    public void compromiseEncryptedMessagePayload(String message) {
    	this.encryptedMessagePayload = message;
	}

	@Override
	public String toString() {
		return encryptedMessagePayload;
	}
}
