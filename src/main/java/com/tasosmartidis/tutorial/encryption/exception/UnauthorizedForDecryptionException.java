package com.tasosmartidis.tutorial.encryption.exception;

public class UnauthorizedForDecryptionException extends RuntimeException {

	public UnauthorizedForDecryptionException(String message, Throwable ex) {
		super(message, ex);
	}
}
