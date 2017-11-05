package com.tasosmartidis.tutorial.encryption.demo;

import com.tasosmartidis.tutorial.encryption.domain.EncryptedMessage;
import com.tasosmartidis.tutorial.encryption.message.RsaMessenger;
import lombok.EqualsAndHashCode;

import java.security.PublicKey;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@EqualsAndHashCode
public class Person {
	private final String id;
	private final String name;
	private final Set<Person> trustedContacts;
	private final RsaMessenger rsaMessenger;

	public Person(String name) {
		this.id = UUID.randomUUID().toString();
		this.name = name;
		this.trustedContacts = new HashSet<>();
		this.rsaMessenger = new RsaMessenger(this.trustedContacts, this.id);
	}

	public PublicKey getPublicKey() {
		return this.rsaMessenger.getPublicKey();
	}

	public String getName() {
		return name;
	}

	public String getId() {
		return id;
	}

	public void addTrustedContact(Person newContact) {
		if(trustedContacts.contains(newContact)) {
			return;
		}

		trustedContacts.add(newContact);
	}

	public EncryptedMessage sendEncryptedMessageToPerson(String message, Person person) {
		return this.rsaMessenger.encryptMessageForPerson(message, person);
	}

	public void readEncryptedMessage(EncryptedMessage encryptedMessage) {
		this.rsaMessenger.readEncryptedMessage(encryptedMessage);
	}

}
