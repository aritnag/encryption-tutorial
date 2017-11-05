package com.tasosmartidis.tutorial.encryption;

import com.tasosmartidis.tutorial.encryption.demo.Person;
import com.tasosmartidis.tutorial.encryption.domain.EncryptedMessage;
import com.tasosmartidis.tutorial.encryption.exception.PayloadAndDigestMismatchException;
import com.tasosmartidis.tutorial.encryption.exception.UnauthorizedForDecryptionException;
import org.junit.Before;
import org.junit.Test;

public class DemoTest {

	private static final String ALICE_MESSAGE_TO_BOB = "Hello Bob";
	private static final String PAULS_MESSAGE_TO_BOB = "Hey there Bob";
	private final Person bob = new Person("Bob");
	private final Person alice = new Person("Alice");
	private final Person paul = new Person("Paul");
	private EncryptedMessage alicesEncryptedMessageToBob;
	private EncryptedMessage paulsEncryptedMessageToBob;

	@Before
	public void setup() {
		bob.addTrustedContact(alice);
		alicesEncryptedMessageToBob = alice.sendEncryptedMessageToPerson(ALICE_MESSAGE_TO_BOB, bob);
		paulsEncryptedMessageToBob = paul.sendEncryptedMessageToPerson(PAULS_MESSAGE_TO_BOB, bob);
	}

	@Test
	public void testBobCanReadAlicesMessage() {
		bob.readEncryptedMessage(alicesEncryptedMessageToBob);
	}

	@Test(expected = UnauthorizedForDecryptionException.class)
	public void testPaulCannotReadAlicesMessageToBob() {
		paul.readEncryptedMessage(alicesEncryptedMessageToBob);
	}

	@Test
	public void testBobCanReadPaulsMessage() {
		bob.readEncryptedMessage(paulsEncryptedMessageToBob);
	}

	@Test(expected = PayloadAndDigestMismatchException.class)
	public void testChangedMessageIdentifiedAndRejected() {
		EncryptedMessage slightlyDifferentMessage = alice.sendEncryptedMessageToPerson(ALICE_MESSAGE_TO_BOB + " ", bob);
		alicesEncryptedMessageToBob.compromiseEncryptedMessagePayload(slightlyDifferentMessage.getEncryptedMessagePayload());

		bob.readEncryptedMessage(alicesEncryptedMessageToBob);
	}
}
