package com.tasosmartidis.tutorial.encryption.exception;

public class DecryptionException extends RuntimeException {

	public DecryptionException(String message, Throwable ex) {
		super(message, ex);
	}
}
