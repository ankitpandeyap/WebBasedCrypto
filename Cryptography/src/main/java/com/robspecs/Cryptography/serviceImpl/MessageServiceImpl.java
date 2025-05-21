package com.robspecs.Cryptography.serviceImpl;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.slf4j.Logger; // Import for Logger
import org.slf4j.LoggerFactory; // Import for LoggerFactory

import com.robspecs.Cryptography.Entities.DecryptionKey;
import com.robspecs.Cryptography.Entities.Message;
import com.robspecs.Cryptography.Entities.User;
import com.robspecs.Cryptography.Enums.Algorithm;
import com.robspecs.Cryptography.dto.MessageRequestDTO;
import com.robspecs.Cryptography.dto.MessageSummaryDTO;
import com.robspecs.Cryptography.factory.EncryptionFactory;
import com.robspecs.Cryptography.repository.DecryptionKeyRepository;
import com.robspecs.Cryptography.repository.MessageRepository;
import com.robspecs.Cryptography.repository.UserRepository;
import com.robspecs.Cryptography.service.EncryptionService;
import com.robspecs.Cryptography.service.MessageService;
import com.robspecs.Cryptography.service.RedisPublisher;
import com.robspecs.Cryptography.utils.KeyGenerator;
import com.robspecs.Cryptography.service.PasskeyCacheService;
import jakarta.transaction.Transactional;

@Service
public class MessageServiceImpl implements MessageService {

	private static final Logger log = LoggerFactory.getLogger(MessageServiceImpl.class); // Logger instance

	private final UserRepository userRepo;
	private final MessageRepository messageRepo;
	private final DecryptionKeyRepository keyRepo;
	private final EncryptionFactory factory;
	private final KeyGenerator keyGen;
	private final RedisPublisher redisPublisher;
	 private final PasswordEncoder passwordEncoder;
	 private final PasskeyCacheService passkeyCacheService;

	public MessageServiceImpl(UserRepository userRepo, MessageRepository messageRepo, DecryptionKeyRepository keyRepo,
			EncryptionFactory factory, KeyGenerator keyGen, RedisPublisher redisPublisher,PasswordEncoder passwordEncoder
			,PasskeyCacheService passkeyCacheService) {
		// super(); // This call is redundant and can be omitted in most modern Java
		// constructors
		this.userRepo = userRepo;
		this.messageRepo = messageRepo;
		this.keyRepo = keyRepo;
		this.factory = factory;
		this.keyGen = keyGen;
		this.redisPublisher = redisPublisher;
		this.passwordEncoder = passwordEncoder;
		this.passkeyCacheService = passkeyCacheService;
		log.info("MessageServiceImpl initialized."); // Constructor logging
	}

	@Override
	@Transactional
	public void sendMessage(MessageRequestDTO req, String senderUsername) throws Exception {
		log.info("Attempting to send message from senderUsername: {} to receiverUsername: {} with algorithm: {}",
				senderUsername, req.getToUsername(), req.getAlgorithm()); // Start method logging

		User sender = userRepo.findByEmailOrUserName(senderUsername).orElseThrow(() -> {
			log.warn("Sender not found for username: {}", senderUsername); // Specific warning for sender not found
			return new RuntimeException("Sender not found");
		});
		log.debug("Sender found: {}", sender.getUserName()); // Debug level for found sender

		User receiver = userRepo.findByEmailOrUserName(req.getToUsername()).orElseThrow(() -> {
			log.warn("Receiver not found for username: {}", req.getToUsername()); // Specific warning for receiver not
																					// found
			return new RuntimeException("Receiver not found");
		});
		log.debug("Receiver found: {}", receiver.getUserName()); // Debug level for found receiver

		Algorithm algo = req.getAlgorithm();
		log.debug("Generating key for algorithm: {}", algo); // Debug for key generation

		String key = keyGen.generate(algo);
		// Do NOT log the actual 'key' at info/debug level as it's sensitive decryption
		// info.
		log.debug("Key generated successfully for algorithm: {}", algo); // Confirm key generation

		String encrypted = null; // Initialize to null for try-catch scope
		try {
			encrypted = factory.getEncryptionService(algo).encrypt(req.getRawMessage(), key);
			log.debug("Message successfully encrypted using algorithm: {}", algo); // Debug for successful encryption
		} catch (Exception e) {
			log.error("Error encrypting message with algorithm {}: {}", algo, e.getMessage(), e); // Error logging with
																									// exception
			throw e; // Re-throw the original exception
		}
		// Do NOT log the actual 'encrypted' message content at info/debug level.

		// Persist Message
		Message msg = new Message();
		msg.setSender(sender);
		msg.setReceiver(receiver);
		msg.setEncryptedContent(encrypted);
		msg.setEncryptionType(algo.name());
		msg.setTimestamp(LocalDateTime.now());
		messageRepo.save(msg);
		log.info("Encrypted message persisted for sender: {} to receiver: {}. Message ID: {}", sender.getUserName(),
				receiver.getUserName(), msg.getMessageId()); // Info for message persistence

		// Persist DecryptionKey
		DecryptionKey dk = new DecryptionKey();
		dk.setMessage(msg);
		dk.setEncryptedKey(key); // Storing the actual key for decryption later
		keyRepo.save(dk);
		log.info("Decryption key persisted for message ID: {}", msg.getMessageId()); // Info for key persistence

		log.info("Message sending process completed successfully for message ID: {}", msg.getMessageId());

		try {
			MessageSummaryDTO summary = new MessageSummaryDTO(msg.getMessageId(), sender.getEmail(),
					msg.getEncryptedContent(), msg.getEncryptionType(), msg.getTimestamp());
			redisPublisher.publishNewMessage(receiver, summary);
			log.debug("Published new-message event to Redis for {}", receiver.getUserName());
		} catch (Exception e) {
			log.error("Failed to publish Redis event for Message[{}]: {}", msg.getMessageId(), e.getMessage(), e);
			// swallow or rethrow depending on your tolerance for delayed notifications

		}

		log.info("sendMessage completed for Message[{}]", msg.getMessageId());
	}

	public List<MessageSummaryDTO> getInboxMessages(User receiver) {
		try {
			log.info("Listing inbox for userId={}", receiver.getUserId());
			List<Message> messages = messageRepo.findByReceiverOrderByTimestampDesc(receiver);

			return messages
					.stream().map(m -> new MessageSummaryDTO(m.getMessageId(), m.getSender().getEmail(),
							m.getEncryptedContent(), m.getEncryptionType(), m.getTimestamp()))
					.collect(Collectors.toList());

		} catch (Exception ex) {
			log.error("Error listing inbox for userId={}: {}", receiver.getUserId(), ex.getMessage(), ex);
			throw new RuntimeException("Could not retrieve inbox messages", ex);
		}
	}

	@Override
	@Transactional
	public String decryptMessage(Long messageId, User currentUser, String passkey) throws Exception {
		log.info("Decrypting messageId={} for userId={}", messageId, currentUser.getUserId());

		// 1. Load the Message and verify receiver
		Message msg = messageRepo.findById(messageId).orElseThrow(() -> {
			log.warn("Message not found: id={}", messageId);
			return new RuntimeException("Message not found");
		});
		if (!msg.getReceiver().getUserId().equals(currentUser.getUserId())) {
			log.warn("Access denied: userId={} is not receiver of messageId={}", currentUser.getUserId(), messageId);
			throw new RuntimeException("Access denied");
		}

		// 2. Verify the passkey
		if (!passwordEncoder.matches(passkey, currentUser.getPasskeyHash())) {
			log.warn("Invalid passkey for userId={}", currentUser.getUserId());
			throw new RuntimeException("Invalid passkey");
		}

		// 3. Fetch the stored encrypted key and decrypt it with AES
		DecryptionKey dk = keyRepo.findByMessage_MessageId(messageId).orElseThrow(() -> {
			log.error("DecryptionKey not found for messageId={}", messageId);
			return new RuntimeException("Decryption key not found");
		});

		String rawKey;
		try {
			// The AES service is identified by @Service("AES")
			EncryptionService aesService = factory.getEncryptionService(Algorithm.AES);
			rawKey = aesService.decrypt(dk.getEncryptedKey(), passkey);
			log.debug("Decryption key successfully retrieved for messageId={}", messageId);
		} catch (Exception e) {
			log.error("Failed to decrypt key for messageId={}: {}", messageId, e.getMessage(), e);
			throw new RuntimeException("Could not decrypt the key");
		}

		// 4. Decrypt the actual message content
		String plainText;
		try {
			EncryptionService contentService = factory.getEncryptionService(Algorithm.valueOf(msg.getEncryptionType()));
			plainText = contentService.decrypt(msg.getEncryptedContent(), rawKey);
			log.info("Message decrypted successfully for messageId={}", messageId);
			return plainText;
		} catch (Exception e) {
			log.error("Failed to decrypt messageId={}: {}", messageId, e.getMessage(), e);
			throw new RuntimeException("Could not decrypt the message");
		}
	}

	@Override
	@Transactional
	public String verifyPasskeyAndGetKey(Long messageId, User currentUser, String passkey) throws Exception {
	    log.info("Verifying passkey for user={} on message={}", currentUser.getUserName(), messageId);

	    // 1. Confirm user is the receiver
	    Message msg = messageRepo.findById(messageId)
	        .orElseThrow(() -> new RuntimeException("Message not found"));
	    if (!msg.getReceiver().getUserId().equals(currentUser.getUserId())) {
	        log.warn("Access denied: user={} is not receiver of msg={}", currentUser.getUserName(), messageId);
	        throw new RuntimeException("Access denied");
	    }

	    // 2. Validate passkey
	    if (!passwordEncoder.matches(passkey, currentUser.getPasskeyHash())) {
	        log.warn("Invalid passkey for user={}", currentUser.getUserName());
	        throw new RuntimeException("Invalid passkey");
	    }

	    // 3. Mark this user as validated
	    passkeyCacheService.markValidated(currentUser.getUserName());

	    // 4. Fetch and decrypt the stored message key
	    DecryptionKey dk = keyRepo.findByMessage_MessageId(messageId)
	        .orElseThrow(() -> new RuntimeException("Decryption key not found"));

	    String rawKey = factory.getEncryptionService(Algorithm.AES)
	                          .decrypt(dk.getEncryptedKey(), passkey);
	    log.info("Passkey verified and raw key retrieved for msg={}", messageId);
	    return rawKey;
	}
	
}