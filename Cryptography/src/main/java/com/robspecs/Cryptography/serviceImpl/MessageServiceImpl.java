package com.robspecs.Cryptography.serviceImpl;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.spec.KeySpec;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import com.robspecs.Cryptography.Entities.DecryptionKey;
import com.robspecs.Cryptography.Entities.Message;
import com.robspecs.Cryptography.Entities.User;
import com.robspecs.Cryptography.Enums.Algorithm;
import com.robspecs.Cryptography.dto.FileDownloadResponseDTO;
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
	public void sendMessage(MessageRequestDTO req, String senderUsername) throws Exception {
		log.info("Attempting to send TEXT message from senderUsername: {} to receiverUsername: {} with algorithm: {}",
				senderUsername, req.getToUsername(), req.getAlgorithm());

		// --- Validation for TEXT message ---
		if (!StringUtils.hasText(req.getRawMessage())) {
			log.error("Text message content is blank for sender: {}", senderUsername);
			throw new IllegalArgumentException("Text message content cannot be empty.");
		}
		if (req.getFile() != null && !req.getFile().isEmpty()) {
			log.error("Received file for text message request for sender: {}", senderUsername);
			throw new IllegalArgumentException(
					"Cannot send a file using the text message endpoint. Use sendFile endpoint.");
		}
		// --- End Validation ---

		User sender = userRepo.findByEmailOrUserName(senderUsername).orElseThrow(() -> {
			log.warn("Sender not found for username: {}", senderUsername);
			return new NotFoundException("Sender not found");
		});
		log.debug("Sender found: {}", sender.getUserName());

		User receiver = userRepo.findByEmailOrUserName(req.getToUsername()).orElseThrow(() -> {
			log.warn("Receiver not found for username: {}", req.getToUsername());
			return new NotFoundException("Receiver not found");
		});
		log.debug("Receiver found: {}", receiver.getUserName());

		// Ensure receiver has a derived encryption key
		if (receiver.getDerivedUserEncryptionKey() == null || receiver.getDerivedUserEncryptionKey().isEmpty()) {
			log.error("Receiver {} does not have a derived encryption key. Cannot send encrypted message.",
					receiver.getUserName());
			throw new MissingEncryptionKeyException(
					"Receiver account is not set up for encrypted messages. Missing encryption key.");
		}

		if (sender.getDerivedUserEncryptionKey() == null || sender.getDerivedUserEncryptionKey().isEmpty()) {
			log.error("Sender {} does not have a derived encryption key. Cannot store key for sender's decryption.",
					sender.getUserName());
			throw new MissingEncryptionKeyException(
					"Sender account is not set up for encrypted messages. Missing encryption key.");
		}

		Algorithm algo = req.getAlgorithm();
		log.debug("Generating symmetric message content key for algorithm: {}", algo);

		String messageContentEncryptionKey = keyGen.generate(algo);
		log.debug("Message content encryption key generated successfully for algorithm: {}", algo);

		byte[] encryptedContentBytes = null; // Change type to byte[]
		try {
			byte[] rawMessageBytes = req.getRawMessage().getBytes(StandardCharsets.UTF_8);
			encryptedContentBytes = factory.getEncryptionService(algo).encrypt(rawMessageBytes,
					messageContentEncryptionKey);
			log.debug("Raw message content successfully encrypted using algorithm: {}", algo);
		} catch (Exception e) {
			log.error("Error encrypting raw message content with algorithm {}: {}", algo, e.getMessage(), e);
			throw new EncryptionDecryptionException("Failed to encrypt message content.", e);
		}

		Message msg = new Message();
		msg.setSender(sender);
		msg.setReceiver(receiver);
		msg.setEncryptedContent(encryptedContentBytes); // <--- Set byte[] directly
		msg.setEncryptionType(algo.name());
		msg.setMessageType("TEXT"); // <--- Set message type as TEXT
		msg.setTimestamp(LocalDateTime.now());
		msg.setRead(false);
		msg.setStarred(false);
		msg.setOriginalFileName(null);
		msg.setContentType(null);
		msg.setFileSize(null);

		messageRepo.save(msg);
		log.info("Encrypted message persisted for sender: {} to receiver: {}. Message ID: {}", sender.getUserName(),
				receiver.getUserName(), msg.getMessageId());

		String receiverDerivedUserAesKeyBase64 = receiver.getDerivedUserEncryptionKey();

		String encryptedMessageKeyForReceiver;
		String encryptedKeyForSender;
		try {
			EncryptionService aesService = factory.getEncryptionService(Algorithm.AES);
			encryptedMessageKeyForReceiver = aesService.encrypt(messageContentEncryptionKey,
					receiverDerivedUserAesKeyBase64);
			log.debug("Message content key encrypted using receiver's derived user key.");

			String senderDerivedUserAesKeyBase64 = sender.getDerivedUserEncryptionKey();
			encryptedKeyForSender = aesService.encrypt(messageContentEncryptionKey, senderDerivedUserAesKeyBase64);
			log.debug("Message content key encrypted using sender's derived user key.");

		} catch (Exception e) {
			log.error("Error encrypting message content key for receiver {}: {}", receiver.getUserName(),
					e.getMessage(), e);
			throw new EncryptionDecryptionException("Failed to secure message key for receiver.", e);
		}

		DecryptionKey dk = new DecryptionKey();
		dk.setMessage(msg);
		dk.setEncryptedKey(encryptedMessageKeyForReceiver);
		dk.setEncryptedKeyForSender(encryptedKeyForSender);
		keyRepo.save(dk);
		log.info("Encrypted message content key persisted for message ID: {}", msg.getMessageId());

		log.info("Message sending process completed successfully for message ID: {}", msg.getMessageId());

		try {
			// --- MODIFICATION: For text messages, pass Base64 encoded encrypted content ---
			MessageSummaryDTO summary = new MessageSummaryDTO(msg.getMessageId(), sender.getUserName(),
					Base64.getEncoder().encodeToString(msg.getEncryptedContent()), // Pass Base64 string for text
					msg.getEncryptionType(), msg.getTimestamp(), receiver.getUserName(), msg.isRead(),
					msg.isStarred());
			// --- END MODIFICATION ---

			log.info("About to call redisPublisher.publishNewMessage for receiver: {}", receiver.getUserName());
			redisPublisher.publishNewMessage(receiver, summary);
			log.info("Successfully called redisPublisher.publishNewMessage for receiver: {}", receiver.getUserName());
			log.debug("Published new-message event to Redis for {}", receiver.getUserName());
		} catch (Exception e) {
			log.error("Failed to publish Redis event for Message[{}]: {}", msg.getMessageId(), e.getMessage(), e);
		}
	}

	@Override
	@Transactional
	public void sendFile(MessageRequestDTO req, String senderUsername) throws Exception {
		log.info("Attempting to send FILE message from senderUsername: {} to receiverUsername: {} with algorithm: {}",
				senderUsername, req.getToUsername(), req.getAlgorithm());

		// --- Validation for FILE message ---
		if (req.getFile() == null || req.getFile().isEmpty()) {
			log.error("File is missing or empty for sender: {}", senderUsername);
			throw new IllegalArgumentException("File content cannot be empty.");
		}
		if (StringUtils.hasText(req.getRawMessage())) {
			log.error("Received text message content for file upload request for sender: {}", senderUsername);
			throw new IllegalArgumentException(
					"Cannot send text content using the file upload endpoint. Use sendMessage endpoint.");
		}
		// --- End Validation ---

		User sender = userRepo.findByEmailOrUserName(senderUsername).orElseThrow(() -> {
			log.warn("Sender not found for username: {}", senderUsername);
			return new NotFoundException("Sender not found");
		});
		log.debug("Sender found: {}", sender.getUserName());

		User receiver = userRepo.findByEmailOrUserName(req.getToUsername()).orElseThrow(() -> {
			log.warn("Receiver not found for username: {}", req.getToUsername());
			return new NotFoundException("Receiver not found");
		});
		log.debug("Receiver found: {}", receiver.getUserName());

		// Ensure receiver has a derived encryption key
		if (receiver.getDerivedUserEncryptionKey() == null || receiver.getDerivedUserEncryptionKey().isEmpty()) {
			log.error("Receiver {} does not have a derived encryption key. Cannot send encrypted file.",
					receiver.getUserName());
			throw new MissingEncryptionKeyException(
					"Receiver account is not set up for encrypted messages. Missing encryption key.");
		}

		if (sender.getDerivedUserEncryptionKey() == null || sender.getDerivedUserEncryptionKey().isEmpty()) {
			log.error("Sender {} does not have a derived encryption key. Cannot store key for sender's decryption.",
					sender.getUserName());
			throw new MissingEncryptionKeyException(
					"Sender account is not set up for encrypted messages. Missing encryption key.");
		}

		Algorithm algo = req.getAlgorithm();
		log.debug("Generating symmetric message content key for algorithm: {}", algo);

		String messageContentEncryptionKey = keyGen.generate(algo);
		log.debug("Message content encryption key generated successfully for algorithm: {}", algo);

		byte[] encryptedContentBytes = null; // Change type to byte[]
		try {
			byte[] fileBytes = req.getFile().getBytes(); // Get file content as bytes
			encryptedContentBytes = factory.getEncryptionService(algo).encrypt(fileBytes, messageContentEncryptionKey);
			log.debug("File content successfully encrypted using algorithm: {}", algo);
		} catch (IOException e) {
			log.error("Error reading file bytes for sender {}: {}", senderUsername, e.getMessage(), e);
			throw new IllegalArgumentException("Failed to read file content.", e);
		} catch (Exception e) {
			log.error("Error encrypting file content with algorithm {}: {}", algo, e.getMessage(), e);
			throw new EncryptionDecryptionException("Failed to encrypt file content.", e);
		}

		Message msg = new Message();
		msg.setSender(sender);
		msg.setReceiver(receiver);
		msg.setEncryptedContent(encryptedContentBytes); // <--- Set byte[] directly
		msg.setEncryptionType(algo.name());
		msg.setMessageType("FILE"); // <--- Set message type as FILE
		msg.setTimestamp(LocalDateTime.now());
		msg.setRead(false);
		msg.setStarred(false);
		// --- Populate NEW File-related fields ---
		msg.setOriginalFileName(req.getFile().getOriginalFilename());
		msg.setContentType(req.getFile().getContentType());
		msg.setFileSize(req.getFile().getSize());

		messageRepo.save(msg);
		log.info("Encrypted file message persisted for sender: {} to receiver: {}. Message ID: {}",
				sender.getUserName(), receiver.getUserName(), msg.getMessageId());

		String receiverDerivedUserAesKeyBase64 = receiver.getDerivedUserEncryptionKey();

		String encryptedMessageKeyForReceiver;
		String encryptedKeyForSender;
		try {
			EncryptionService aesService = factory.getEncryptionService(Algorithm.AES);
			encryptedMessageKeyForReceiver = aesService.encrypt(messageContentEncryptionKey,
					receiverDerivedUserAesKeyBase64);
			log.debug("Message content key encrypted using receiver's derived user key.");

			String senderDerivedUserAesKeyBase64 = sender.getDerivedUserEncryptionKey();
			encryptedKeyForSender = aesService.encrypt(messageContentEncryptionKey, senderDerivedUserAesKeyBase64);
			log.debug("Message content key encrypted using sender's derived user key.");

		} catch (Exception e) {
			log.error("Error encrypting message content key for receiver {}: {}", receiver.getUserName(),
					e.getMessage(), e);
			throw new EncryptionDecryptionException("Failed to secure message key for receiver.", e);
		}

		DecryptionKey dk = new DecryptionKey();
		dk.setMessage(msg);
		dk.setEncryptedKey(encryptedMessageKeyForReceiver);
		dk.setEncryptedKeyForSender(encryptedKeyForSender);
		keyRepo.save(dk);
		log.info("Encrypted message content key persisted for message ID: {}", msg.getMessageId());

		log.info("File sending process completed successfully for message ID: {}", msg.getMessageId());

		try {
			// --- MODIFICATION: For file messages, use the file-specific constructor ---
			MessageSummaryDTO summary = new MessageSummaryDTO(msg.getMessageId(), sender.getUserName(),
					msg.getEncryptionType(), msg.getTimestamp(), receiver.getUserName(), msg.isRead(), msg.isStarred(),
					true, // isFile is true for file messages
					msg.getOriginalFileName(), msg.getContentType());
			// --- END MODIFICATION ---

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
			return messages.stream().map(m -> {
				boolean isFileMessage = "FILE".equals(m.getMessageType());

				if (isFileMessage) {
					// --- MODIFICATION: For files, use the file-specific constructor, encryptedContent is null ---
					return new MessageSummaryDTO(m.getMessageId(), m.getSender().getUserName(), m.getEncryptionType(),
							m.getTimestamp(), receiver.getUserName(), m.isRead(), m.isStarred(), true,
							m.getOriginalFileName(), m.getContentType());
				} else {
					// --- MODIFICATION: For text, pass Base64 encoded encrypted content ---
					String encodedContent = (m.getEncryptedContent() != null)
							? Base64.getEncoder().encodeToString(m.getEncryptedContent())
							: null;
					return new MessageSummaryDTO(m.getMessageId(), m.getSender().getUserName(), encodedContent,
							m.getEncryptionType(), m.getTimestamp(), receiver.getUserName(), m.isRead(),
							m.isStarred());
				}
			}).collect(Collectors.toList());

		} catch (InboxRetrievalException ex) {
			throw ex;
		} catch (Exception ex) {
			log.error("Failed to retrieve inbox messages for user {}: {}", receiver.getUserName(), ex.getMessage(), ex);
			throw new InboxRetrievalException("Failed to retrieve inbox messages for user: " + receiver.getUserName(),
					ex);
		}
	}

	@Override
	@Transactional
	public FileDownloadResponseDTO downloadFile(Long messageId, User currentUser, String passkey) throws Exception {
		log.info("Attempting to download file for messageId={} for userId={}", messageId, currentUser.getUserId());

		Message msg = messageRepo.findById(messageId).orElseThrow(() -> {
			log.warn("Message not found: id={}", messageId);
			return new NotFoundException("Message not found");
		});

		// Authorization check: User must be either the sender or the receiver
		if (!msg.getReceiver().getUserId().equals(currentUser.getUserId())
				&& !msg.getSender().getUserId().equals(currentUser.getUserId())) {
			log.warn("Access denied: userId={} is neither receiver nor sender of messageId={}", currentUser.getUserId(),
					messageId);
			throw new UnauthorizedException("Access denied: You are not authorized to download this file.");
		}

		if (!"FILE".equals(msg.getMessageType()) || msg.getEncryptedContent() == null
				|| msg.getEncryptedContent().length == 0) {
			log.warn("Message ID {} is not a file message (messageType: {}) or content is missing.", messageId,
					msg.getMessageType());
			throw new IllegalArgumentException("This message is not a file, or file content is missing.");
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
					throw new InvalidPasskeyException("Invalid passkey provided. Please try again.");
				}
				log.debug(
						"Provided passkey verified against stored derived encryption key for userId={}. Marking as validated.",
						currentUser.getUserId());
				userEncryptionKey = derivedKeyFromInput;

				passkeyCacheService.markValidated(currentUser.getUsername());
			}

			DecryptionKey dk = keyRepo.findByMessage_MessageId(messageId).orElseThrow(() -> {
				log.error("DecryptionKey not found for messageId={}", messageId);
				return new NotFoundException("Decryption key not found for this message.");
			});

			EncryptionService aesService = factory.getEncryptionService(Algorithm.AES);
			if (msg.getReceiver().getUserId().equals(currentUser.getUserId())) {
				messageContentEncryptionKey = aesService.decrypt(dk.getEncryptedKey(), userEncryptionKey);
				log.debug("Message content key decrypted using receiver's derived user key for messageId={}",
						messageId);
			} else {
				messageContentEncryptionKey = aesService.decrypt(dk.getEncryptedKeyForSender(), userEncryptionKey);
				log.debug("Message content key decrypted using sender's derived user key for messageId={}", messageId);
			}

		} catch (Exception e) {
			log.warn("Failed to decrypt message key for messageId={} using provided passkey. Error: {}", messageId,
					e.getMessage(), e);
			throw new EncryptionDecryptionException("Could not decrypt the file key. Please check your passkey.", e);
		}

		byte[] decryptedFileBytes;
		try {
			EncryptionService contentService = factory.getEncryptionService(Algorithm.valueOf(msg.getEncryptionType()));
			byte[] encryptedContentBytes = msg.getEncryptedContent();
			decryptedFileBytes = contentService.decrypt(encryptedContentBytes, messageContentEncryptionKey);
			log.info("File content decrypted successfully for messageId={}", messageId);

			if (msg.getReceiver().getUserId().equals(currentUser.getUserId()) && !msg.isRead()) {
				messageRepo.updateIsReadStatus(messageId, currentUser, true);
				log.info("Message ID: {} marked as read after file download by user: {}", messageId,
						currentUser.getUserName());
			}

			return new FileDownloadResponseDTO(new ByteArrayResource(decryptedFileBytes), msg.getOriginalFileName(),
					msg.getContentType());

		} catch (Exception e) {
			log.error("Failed to decrypt file content for messageId={}: {}", messageId, e.getMessage(), e);
			throw new EncryptionDecryptionException("Could not decrypt the file content. File might be corrupted.", e);
		}
	}

	@Override
	public List<MessageSummaryDTO> getSentMessages(User sender) {
		try {
			log.info("Listing sent messages for userId={}", sender.getUserId());
			List<Message> messages = messageRepo.findBySenderOrderByTimestampDesc(sender);

			return messages.stream().map(m -> {
				boolean isFileMessage = "FILE".equals(m.getMessageType());

				if (isFileMessage) {
					// --- MODIFICATION: For files, use the file-specific constructor, encryptedContent is null ---
					return new MessageSummaryDTO(m.getMessageId(), sender.getUserName(), m.getEncryptionType(),
							m.getTimestamp(), m.getReceiver().getUserName(), m.isRead(), m.isStarred(), true,
							m.getOriginalFileName(), m.getContentType());
				} else {
					// --- MODIFICATION: For text, pass Base64 encoded encrypted content ---
					String encodedContent = (m.getEncryptedContent() != null)
							? Base64.getEncoder().encodeToString(m.getEncryptedContent())
							: null;
					return new MessageSummaryDTO(m.getMessageId(), sender.getUserName(), encodedContent,
							m.getEncryptionType(), m.getTimestamp(), m.getReceiver().getUserName(), m.isRead(),
							m.isStarred());
				}
			}).collect(Collectors.toList());
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
			return new NotFoundException("Message not found");
		});

		if (!"TEXT".equals(msg.getMessageType())) {
			log.warn("Message ID {} is not a text message (messageType: {}). Use the file download endpoint.",
					messageId, msg.getMessageType());
			throw new IllegalArgumentException("This message is a file. Please use the file download endpoint.");
		}

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
					"Your account is not fully set up for decryption. Please contact support.");
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
					throw new InvalidPasskeyException("Invalid passkey provided. Please try again.");
				}
				log.debug(
						"Provided passkey verified against stored derived encryption key for userId={}. Marking as validated.",
						currentUser.getUserId());
				userEncryptionKey = derivedKeyFromInput;

				passkeyCacheService.markValidated(currentUser.getUsername());
			}

			DecryptionKey dk = keyRepo.findByMessage_MessageId(messageId).orElseThrow(() -> {
				log.error("DecryptionKey not found for messageId={}", messageId);
				return new NotFoundException("Decryption key not found for this message.");
			});

			EncryptionService aesService = factory.getEncryptionService(Algorithm.AES);
			if (msg.getReceiver().getUserId().equals(currentUser.getUserId())) {
				messageContentEncryptionKey = aesService.decrypt(dk.getEncryptedKey(), userEncryptionKey);
				log.debug("Message content key decrypted using receiver's derived user key for messageId={}",
						messageId);
			} else {
				messageContentEncryptionKey = aesService.decrypt(dk.getEncryptedKeyForSender(), userEncryptionKey);
				log.debug("Message content key decrypted using sender's derived user key for messageId={}", messageId);
			}

		} catch (Exception e) {
			log.warn("Failed to decrypt message key for messageId={} using provided passkey. Error: {}", messageId,
					e.getMessage(), e);
			throw new EncryptionDecryptionException("Could not decrypt the message key. Please check your passkey.", e);
		}

		String plainText;
		try {
			EncryptionService contentService = factory.getEncryptionService(Algorithm.valueOf(msg.getEncryptionType()));
			byte[] encryptedContentBytes = msg.getEncryptedContent();

			byte[] decryptedBytes = contentService.decrypt(encryptedContentBytes, messageContentEncryptionKey);

			plainText = new String(decryptedBytes, StandardCharsets.UTF_8);

			log.info("Message content decrypted successfully for messageId={}", messageId);
			return plainText;
		} catch (Exception e) {
			log.error("Failed to decrypt message content for messageId={}: {}", messageId, e.getMessage(), e);
			throw new EncryptionDecryptionException("Could not decrypt the message content. Data might be corrupted.",
					e);
		}
	}

	@Override
	@Transactional
	public String verifyPasskeyAndGetKey(Long messageId, User currentUser, String passkey) throws Exception {
		log.info("Verifying passkey for user={} on message={}", currentUser.getUserName(), messageId);

		Message msg = messageRepo.findById(messageId).orElseThrow(() -> new NotFoundException("Message not found"));

		// This endpoint is primarily for getting the decryption key, not direct content.
		// It's still valid for files, as the key is needed for download too.
		// Remove the TEXT-only validation here if you need to use this for files to get the key.
		// For now, I'll assume you want to allow it for both, as the key is universally needed.
		// If you want to restrict it, re-add the "if (!"TEXT".equals(msg.getMessageType()))" check.


		if (!msg.getReceiver().getUserId().equals(currentUser.getUserId())
				&& !msg.getSender().getUserId().equals(currentUser.getUserId())) {
			log.warn("Access denied: userId={} is neither receiver nor sender of msg={}", currentUser.getUserId(),
					messageId);
			throw new UnauthorizedException(
					"Access denied: You are not authorized to verify passkey for this message.");
		}

		if (currentUser.getPasskeySalt() == null || currentUser.getPasskeySalt().isEmpty()
				|| currentUser.getDerivedUserEncryptionKey() == null
				|| currentUser.getDerivedUserEncryptionKey().isEmpty()) {
			log.error("User {} is missing encryption key components (salt or derived key) for verification.",
					currentUser.getUserName());
			throw new MissingEncryptionKeyException("Your account is not fully set up for decryption.");
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
				throw new InvalidPasskeyException("Invalid passkey provided. Please try again.");
			}
			log.debug("Provided passkey verified against stored derived encryption key for userId={}",
					currentUser.getUserId());

			DecryptionKey dk = keyRepo.findByMessage_MessageId(messageId)
					.orElseThrow(() -> new NotFoundException("Decryption key not found for this message."));

			EncryptionService aesService = factory.getEncryptionService(Algorithm.AES);

			if (msg.getReceiver().getUserId().equals(currentUser.getUserId())) {
				messageContentEncryptionKey = aesService.decrypt(dk.getEncryptedKey(), derivedUserKeyFromInputPasskey);
				log.debug(
						"Message content key decrypted using receiver's derived user key for verification (messageId={})",
						messageId);
			} else {
				messageContentEncryptionKey = aesService.decrypt(dk.getEncryptedKeyForSender(), derivedUserKeyFromInputPasskey);
				log.debug("Message content key decrypted using sender's derived user key for verification (messageId={})", messageId);
			}

			log.debug("Message content encryption key successfully decrypted for verification for messageId={}",
					messageId);

		} catch (Exception e) {
			log.warn("Passkey verification failed for msgId={} for user {}. Error: {}", messageId,
					currentUser.getUserName(), e.getMessage(), e);
			throw new EncryptionDecryptionException("Passkey verification failed.", e);
		}

		passkeyCacheService.markValidated(currentUser.getUserName());
		log.info("Passkey verified and message content key retrieved for msg={}", messageId);
		return messageContentEncryptionKey;
	}

	@Override
	@Transactional
	public void markMessageAsRead(Long messageId, String currentUsername) {
		User currentUser = userRepo.findByEmailOrUserName(currentUsername)
				.orElseThrow(() -> new NotFoundException("User not found: " + currentUsername));

		messageRepo.findByMessageIdAndReceiver(messageId, currentUser)
				.orElseThrow(() -> new UnauthorizedException("You are not authorized to mark this message as read, or message not found."));

		messageRepo.updateIsReadStatus(messageId, currentUser, true);
		log.info("Message ID: {} marked as read by user: {}", messageId, currentUsername);
	}

	@Override
	@Transactional
	public void toggleMessageStarred(Long messageId, String currentUsername) {
		User currentUser = userRepo.findByEmailOrUserName(currentUsername)
				.orElseThrow(() -> new NotFoundException("User not found: " + currentUsername));

		Message message = messageRepo.findById(messageId)
				.orElseThrow(() -> new NotFoundException("Message not found with ID: " + messageId));

		if (!message.getSender().getUserId().equals(currentUser.getUserId())
				&& !message.getReceiver().getUserId().equals(currentUser.getUserId())) {
			log.warn("Access denied: User {} is neither sender nor receiver of message ID {}", currentUsername,
					messageId);
			throw new UnauthorizedException("You are not authorized to star/unstar this message.");
		}

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
		Message message = messageRepo.findById(messageId)
				.orElseThrow(() -> new NotFoundException("Message not found with ID: " + messageId));
		if (!message.getSender().getUserId().equals(currentUser.getUserId())
				&& !message.getReceiver().getUserId().equals(currentUser.getUserId())) {
			log.warn("Access denied: User {} is neither sender nor receiver of message ID {}", currentUsername,
					messageId);
			throw new UnauthorizedException("You are not authorized to delete this message.");
		}
		messageRepo.delete(message);
		log.info("Message ID: {} hard deleted by user: {}", messageId, currentUsername);
	}
}