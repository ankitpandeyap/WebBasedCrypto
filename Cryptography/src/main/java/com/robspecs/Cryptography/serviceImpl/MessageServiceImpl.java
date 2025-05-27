package com.robspecs.Cryptography.serviceImpl;

import java.security.spec.KeySpec;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.slf4j.Logger; // Import for Logger
import org.slf4j.LoggerFactory; // Import for LoggerFactory
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.robspecs.Cryptography.Entities.DecryptionKey;
import com.robspecs.Cryptography.Entities.Message;
import com.robspecs.Cryptography.Entities.User;
import com.robspecs.Cryptography.Enums.Algorithm;
import com.robspecs.Cryptography.dto.MessageRequestDTO;
import com.robspecs.Cryptography.dto.MessageSummaryDTO;
import com.robspecs.Cryptography.exceptions.EncryptionDecryptionException;
import com.robspecs.Cryptography.exceptions.InboxRetrievalException;
import com.robspecs.Cryptography.exceptions.InvalidPasskeyException;
import com.robspecs.Cryptography.exceptions.MissingEncryptionKeyException;
import com.robspecs.Cryptography.exceptions.NotFoundException;
import com.robspecs.Cryptography.exceptions.UnauthorizedException;
import com.robspecs.Cryptography.factory.EncryptionFactory;
import com.robspecs.Cryptography.repository.DecryptionKeyRepository;
import com.robspecs.Cryptography.repository.MessageRepository;
import com.robspecs.Cryptography.repository.UserRepository;
import com.robspecs.Cryptography.service.EncryptionService;
import com.robspecs.Cryptography.service.MessageService;
import com.robspecs.Cryptography.service.PasskeyCacheService;
import com.robspecs.Cryptography.service.RedisPublisher;
import com.robspecs.Cryptography.utils.KeyGenerator;

import jakarta.transaction.Transactional;

@Service
public class MessageServiceImpl implements MessageService {

	private static final Logger log = LoggerFactory.getLogger(MessageServiceImpl.class);

	private final UserRepository userRepo;
	private final MessageRepository messageRepo;
	private final DecryptionKeyRepository keyRepo;
	private final EncryptionFactory factory;
	private final KeyGenerator keyGen;
	private final RedisPublisher redisPublisher;
	private final PasswordEncoder passwordEncoder;
	private final PasskeyCacheService passkeyCacheService;

	@Value("${security.pbkdf2.iterations:65536}")
	private int pbkdf2Iterations;

	public MessageServiceImpl(UserRepository userRepo, MessageRepository messageRepo, DecryptionKeyRepository keyRepo,
			EncryptionFactory factory, KeyGenerator keyGen, RedisPublisher redisPublisher,
			PasswordEncoder passwordEncoder, PasskeyCacheService passkeyCacheService) {
		this.userRepo = userRepo;
		this.messageRepo = messageRepo;
		this.keyRepo = keyRepo;
		this.factory = factory;
		this.keyGen = keyGen;
		this.redisPublisher = redisPublisher;
		this.passwordEncoder = passwordEncoder;
		this.passkeyCacheService = passkeyCacheService;
		log.info("MessageServiceImpl initialized.");
	}

	@Override
	@Transactional
	public void sendMessage(MessageRequestDTO req, String senderUsername) throws Exception { // Keep throws Exception
																								// for now, will refine
																								// in controller
		log.info("Attempting to send message from senderUsername: {} to receiverUsername: {} with algorithm: {}",
				senderUsername, req.getToUsername(), req.getAlgorithm());

		User sender = userRepo.findByEmailOrUserName(senderUsername).orElseThrow(() -> {
			log.warn("Sender not found for username: {}", senderUsername);
			return new NotFoundException("Sender not found"); // Changed to NotFoundException
		});
		log.debug("Sender found: {}", sender.getUserName());

		User receiver = userRepo.findByEmailOrUserName(req.getToUsername()).orElseThrow(() -> {
			log.warn("Receiver not found for username: {}", req.getToUsername());
			return new NotFoundException("Receiver not found"); // Changed to NotFoundException
		});
		log.debug("Receiver found: {}", receiver.getUserName());

		// Ensure receiver has a derived encryption key
		if (receiver.getDerivedUserEncryptionKey() == null || receiver.getDerivedUserEncryptionKey().isEmpty()) {
			log.error("Receiver {} does not have a derived encryption key. Cannot send encrypted message.",
					receiver.getUserName());
			throw new MissingEncryptionKeyException( // Changed to MissingEncryptionKeyException
					"Receiver account is not set up for encrypted messages. Missing encryption key.");
		}

		Algorithm algo = req.getAlgorithm();
		log.debug("Generating symmetric message content key for algorithm: {}", algo);

		String messageContentEncryptionKey = keyGen.generate(algo);
		log.debug("Message content encryption key generated successfully for algorithm: {}", algo);

		String encryptedContent = null;
		try {
			encryptedContent = factory.getEncryptionService(algo).encrypt(req.getRawMessage(),
					messageContentEncryptionKey);
			log.debug("Raw message content successfully encrypted using algorithm: {}", algo);
		} catch (Exception e) {
			log.error("Error encrypting raw message content with algorithm {}: {}", algo, e.getMessage(), e);
			throw new EncryptionDecryptionException("Failed to encrypt message content.", e); // Changed to
																								// EncryptionDecryptionException
		}

		Message msg = new Message();
		msg.setSender(sender);
		msg.setReceiver(receiver);
		msg.setEncryptedContent(encryptedContent);
		msg.setEncryptionType(algo.name());
		msg.setTimestamp(LocalDateTime.now());
		msg.setRead(false);
		msg.setStarred(false);
		messageRepo.save(msg);		
		log.info("Encrypted message persisted for sender: {} to receiver: {}. Message ID: {}", sender.getUserName(),
				receiver.getUserName(), msg.getMessageId());

		String receiverDerivedUserAesKeyBase64 = receiver.getDerivedUserEncryptionKey();

		String encryptedMessageKeyForReceiver;
		try {
			EncryptionService aesService = factory.getEncryptionService(Algorithm.AES);
			encryptedMessageKeyForReceiver = aesService.encrypt(messageContentEncryptionKey,
					receiverDerivedUserAesKeyBase64);
			log.debug("Message content key encrypted using receiver's derived user key.");
		} catch (Exception e) {
			log.error("Error encrypting message content key for receiver {}: {}", receiver.getUserName(),
					e.getMessage(), e);
			throw new EncryptionDecryptionException("Failed to secure message key for receiver.", e); // Changed to
																										// EncryptionDecryptionException
		}

		DecryptionKey dk = new DecryptionKey();
		dk.setMessage(msg);
		dk.setEncryptedKey(encryptedMessageKeyForReceiver);
		keyRepo.save(dk);
		log.info("Encrypted message content key persisted for message ID: {}", msg.getMessageId());

		log.info("Message sending process completed successfully for message ID: {}", msg.getMessageId());

		try {
			MessageSummaryDTO summary = new MessageSummaryDTO(msg.getMessageId(), sender.getUserName(),
					msg.getEncryptedContent(), msg.getEncryptionType(), msg.getTimestamp(), receiver.getUserName(),
					msg.isRead(), // Include isRead
					msg.isStarred() // --- NEW: Include isStarred status for Redis ---
			);

			log.info("About to call redisPublisher.publishNewMessage for receiver: {}", receiver.getUserName());
			redisPublisher.publishNewMessage(receiver, summary);
			log.info("Successfully called redisPublisher.publishNewMessage for receiver: {}", receiver.getUserName());
			log.debug("Published new-message event to Redis for {}", receiver.getUserName());
		} catch (Exception e) {
			log.error("Failed to publish Redis event for Message[{}]: {}", msg.getMessageId(), e.getMessage(), e);
		}
	}

	@Override
	public List<MessageSummaryDTO> getInboxMessages(User receiver) {
		try {
			log.info("Listing inbox for userId={}", receiver.getUserId());
			List<Message> messages = messageRepo.findByReceiverOrderByTimestampDesc(receiver);
			return messages.stream().map(m -> new MessageSummaryDTO(m.getMessageId(), m.getSender().getUserName(),
					m.getEncryptedContent(), m.getEncryptionType(), m.getTimestamp(), receiver.getUserName(),
					m.isRead(),
					m.isStarred()
			)).collect(Collectors.toList());


		} catch (InboxRetrievalException ex) {
			throw ex;
		} catch (Exception ex) {
			log.error("Failed to retrieve inbox messages for user {}: {}", receiver.getUserName(), ex.getMessage(), ex);
			throw new InboxRetrievalException("Failed to retrieve inbox messages for user: " + receiver.getUserName(),
					ex);
		}
	}
	@Override
	public List<MessageSummaryDTO> getSentMessages(User sender) {
		try {
			log.info("Listing sent messages for userId={}", sender.getUserId());
			List<Message> messages = messageRepo.findBySenderOrderByTimestampDesc(sender);

			return messages.stream().map(m -> new MessageSummaryDTO(m.getMessageId(), sender.getUserName(),
					m.getEncryptedContent(), m.getEncryptionType(), m.getTimestamp(), m.getReceiver().getUserName(),
					m.isRead(), // Include isRead
					m.isStarred()
			)).collect(Collectors.toList());
		} catch (Exception ex) {
			log.error("Failed to retrieve sent messages for user {}: {}", sender.getUserName(), ex.getMessage(), ex);
			throw new InboxRetrievalException("Failed to retrieve sent messages for user: " + sender.getUserName(), ex);
		}
	}

	@Override
	@Transactional
	public String decryptMessage(Long messageId, User currentUser, String passkey) throws Exception {

		log.info("Attempting to decrypt messageId={} for userId={}", messageId, currentUser.getUserId());

		Message msg = messageRepo.findById(messageId).orElseThrow(() -> {
			log.warn("Message not found: id={}", messageId);
			return new NotFoundException("Message not found"); // Changed to NotFoundException
		});
		if (!msg.getReceiver().getUserId().equals(currentUser.getUserId())
				&& !msg.getSender().getUserId().equals(currentUser.getUserId())) {
			log.warn("Access denied: userId={} is neither receiver nor sender of messageId={}", currentUser.getUserId(),
					messageId);
			throw new UnauthorizedException("Access denied: You are not authorized to decrypt this message.");
		}
		if (currentUser.getPasskeySalt() == null || currentUser.getPasskeySalt().isEmpty()
				|| currentUser.getDerivedUserEncryptionKey() == null
				|| currentUser.getDerivedUserEncryptionKey().isEmpty()) {
			log.error("User {} is missing encryption key components (salt or derived key).", currentUser.getUserName());
			throw new MissingEncryptionKeyException(
					"Your account is not fully set up for decryption. Please contact support."); // Changed to
																									// MissingEncryptionKeyException
		}

		String userEncryptionKey;
		String messageContentEncryptionKey;

		try {
			if (passkeyCacheService.isValidated(currentUser.getUsername())) {
				log.debug("Passkey for user {} is cached as validated. Using stored derived encryption key.",
						currentUser.getUserName());
				userEncryptionKey = currentUser.getDerivedUserEncryptionKey();
			} else {
				log.debug("Passkey for user {} is NOT cached as validated. Performing PBKDF2 derivation.",
						currentUser.getUserName());
				byte[] passkeySaltBytes = Base64.getDecoder().decode(currentUser.getPasskeySalt());
				SecretKeyFactory factoryPBKDF2 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
				KeySpec spec = new PBEKeySpec(passkey.toCharArray(), passkeySaltBytes, pbkdf2Iterations, 256);
				SecretKey secret = factoryPBKDF2.generateSecret(spec);
				String derivedKeyFromInput = Base64.getEncoder().encodeToString(secret.getEncoded());

				if (!derivedKeyFromInput.equals(currentUser.getDerivedUserEncryptionKey())) {
					log.warn(
							"Provided passkey for userId={} does not match the stored derived encryption key. Invalid passkey.",
							currentUser.getUserId());
					throw new InvalidPasskeyException("Invalid passkey provided. Please try again."); // Changed to
																										// InvalidPasskeyException
				}
				log.debug(
						"Provided passkey verified against stored derived encryption key for userId={}. Marking as validated.",
						currentUser.getUserId());
				userEncryptionKey = derivedKeyFromInput;

				passkeyCacheService.markValidated(currentUser.getUsername());
			}

			DecryptionKey dk = keyRepo.findByMessage_MessageId(messageId).orElseThrow(() -> {
				log.error("DecryptionKey not found for messageId={}", messageId);
				return new NotFoundException("Decryption key not found for this message."); // Changed to
																							// NotFoundException
			});

			EncryptionService aesService = factory.getEncryptionService(Algorithm.AES);
			messageContentEncryptionKey = aesService.decrypt(dk.getEncryptedKey(), userEncryptionKey);
			log.debug("Message content encryption key successfully decrypted for messageId={}", messageId);

		} catch (Exception e) { // Catching generic Exception here is still broad, but it will wrap specific
								// crypto errors
			log.warn("Failed to decrypt message key for messageId={} using provided passkey. Error: {}", messageId,
					e.getMessage(), e);
			throw new EncryptionDecryptionException("Could not decrypt the message key. Please check your passkey.", e); // Changed
																															// to
																															// EncryptionDecryptionException
		}

		String plainText;
		try {
			EncryptionService contentService = factory.getEncryptionService(Algorithm.valueOf(msg.getEncryptionType()));
			plainText = contentService.decrypt(msg.getEncryptedContent(), messageContentEncryptionKey);
			log.info("Message content decrypted successfully for messageId={}", messageId);
			return plainText;
		} catch (Exception e) { // Catching generic Exception here is still broad, but it will wrap specific
								// crypto errors
			log.error("Failed to decrypt message content for messageId={}: {}", messageId, e.getMessage(), e);
			throw new EncryptionDecryptionException("Could not decrypt the message content. Data might be corrupted.",
					e); // Changed to EncryptionDecryptionException
		}
	}

	@Override
	@Transactional
	public String verifyPasskeyAndGetKey(Long messageId, User currentUser, String passkey) throws Exception { 
		log.info("Verifying passkey for user={} on message={}", currentUser.getUserName(), messageId);

		Message msg = messageRepo.findById(messageId).orElseThrow(() -> new NotFoundException("Message not found")); // Changed
																														// to
																														// NotFoundException
		if (!msg.getReceiver().getUserId().equals(currentUser.getUserId())) {
			log.warn("Access denied: user={} is not receiver of msg={}", currentUser.getUserName(), messageId);
			// Changed to UnauthorizedException, which now maps to 403 Forbidden
			throw new UnauthorizedException("Access denied: You are not the receiver of this message.");
		}

		if (currentUser.getPasskeySalt() == null || currentUser.getPasskeySalt().isEmpty()
				|| currentUser.getDerivedUserEncryptionKey() == null
				|| currentUser.getDerivedUserEncryptionKey().isEmpty()) {
			log.error("User {} is missing encryption key components (salt or derived key) for verification.",
					currentUser.getUserName());
			throw new MissingEncryptionKeyException("Your account is not fully set up for decryption."); // Changed to
																											// MissingEncryptionKeyException
		}

		String messageContentEncryptionKey;
		try {
			byte[] passkeySaltBytes = Base64.getDecoder().decode(currentUser.getPasskeySalt());
			SecretKeyFactory factoryPBKDF2 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
			KeySpec spec = new PBEKeySpec(passkey.toCharArray(), passkeySaltBytes, pbkdf2Iterations, 256);
			SecretKey secret = factoryPBKDF2.generateSecret(spec);
			String derivedUserKeyFromInputPasskey = Base64.getEncoder().encodeToString(secret.getEncoded());

			if (!derivedUserKeyFromInputPasskey.equals(currentUser.getDerivedUserEncryptionKey())) {
				log.warn(
						"Provided passkey for userId={} does not match the stored derived encryption key during verification.",
						currentUser.getUserId());
				throw new InvalidPasskeyException("Invalid passkey provided. Please try again."); // Changed to
																									// InvalidPasskeyException
			}
			log.debug("Provided passkey verified against stored derived encryption key for userId={}",
					currentUser.getUserId());

			DecryptionKey dk = keyRepo.findByMessage_MessageId(messageId)
					.orElseThrow(() -> new NotFoundException("Decryption key not found for this message.")); // Changed
																												// to
																												// NotFoundException

			EncryptionService aesService = factory.getEncryptionService(Algorithm.AES);
			messageContentEncryptionKey = aesService.decrypt(dk.getEncryptedKey(), derivedUserKeyFromInputPasskey);
			log.debug("Message content encryption key successfully decrypted for verification for messageId={}",
					messageId);

		} catch (Exception e) {
			log.warn("Passkey verification failed for msgId={} for user {}. Error: {}", messageId,
					currentUser.getUserName(), e.getMessage(), e);
			throw new EncryptionDecryptionException("Passkey verification failed.", e); // Changed to
																						// EncryptionDecryptionException
		}

		passkeyCacheService.markValidated(currentUser.getUserName());
		log.info("Passkey verified and message content key retrieved for msg={}", messageId);
		return messageContentEncryptionKey;
	}

	@Override
    @Transactional
    public void markMessageAsRead(Long messageId, String currentUsername) {
        User currentUser = userRepo.findByEmailOrUserName(currentUsername) // Using userRepo.findByUserName as per your code
                .orElseThrow(() -> new NotFoundException("User not found: " + currentUsername));

        // Validate that the message exists and belongs to the current user (as receiver)
        // Using findByMessageIdAndReceiver as per your updated MessageRepository
        messageRepo.findByMessageIdAndReceiver(messageId, currentUser)
                .orElseThrow(() -> new UnauthorizedException("You are not authorized to mark this message as read, or message not found."));

        // Call the repository method to update the status
        messageRepo.updateIsReadStatus(messageId, currentUser, true);
        log.info("Message ID: {} marked as read by user: {}", messageId, currentUsername);
    }

	@Override
	@Transactional
	public void toggleMessageStarred(Long messageId, String currentUsername) {
		User currentUser = userRepo.findByEmailOrUserName(currentUsername)
				.orElseThrow(() -> new NotFoundException("User not found: " + currentUsername));

		// Find the message by its ID.
		// We'll then check if the current user is either the sender or receiver.
		Message message = messageRepo.findById(messageId)
				.orElseThrow(() -> new NotFoundException("Message not found with ID: " + messageId));

		// Authorization: User must be either the sender or the receiver to star/unstar
		// it.
		if (!message.getSender().getUserId().equals(currentUser.getUserId())
				&& !message.getReceiver().getUserId().equals(currentUser.getUserId())) {
			log.warn("Access denied: User {} is neither sender nor receiver of message ID {}", currentUsername,
					messageId);
			throw new UnauthorizedException("You are not authorized to star/unstar this message.");
		}

		// Toggle the starred status
		boolean newStarredStatus = !message.isStarred();
		messageRepo.updateIsStarredStatus(messageId, currentUser, newStarredStatus);
		log.info("Message ID: {} starred status toggled to {} by user: {}", messageId, newStarredStatus,
				currentUsername);
	}

	@Override
	@Transactional
	public void deleteMessage(Long messageId, String currentUsername) {
		User currentUser = userRepo.findByEmailOrUserName(currentUsername)
				.orElseThrow(() -> new NotFoundException("User not found: " + currentUsername));

		// Find the message by its ID to perform authorization check
		Message message = messageRepo.findById(messageId)
				.orElseThrow(() -> new NotFoundException("Message not found with ID: " + messageId));

		// Authorization: User must be either the sender or the receiver to delete it.
		if (!message.getSender().getUserId().equals(currentUser.getUserId())
				&& !message.getReceiver().getUserId().equals(currentUser.getUserId())) {
			log.warn("Access denied: User {} is neither sender nor receiver of message ID {}", currentUsername,
					messageId);
			throw new UnauthorizedException("You are not authorized to delete this message.");
		}

		// --- PERFORM HARD DELETE ---
		// This will delete the message row from the database permanently.
		// It's crucial that `CascadeType.ALL` is correctly set on `Message` entity's
		// `decryptionKey` field to also delete the associated decryption key.
		//messageRepo.deleteMessageByIdAndUser(messageId, currentUser);
		messageRepo.delete(message);
		log.info("Message ID: {} hard deleted by user: {}", messageId, currentUsername);
	}
}
