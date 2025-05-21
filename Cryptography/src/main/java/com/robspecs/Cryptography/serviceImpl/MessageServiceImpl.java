package com.robspecs.Cryptography.serviceImpl;

import java.time.LocalDateTime;

import org.springframework.stereotype.Service;
import org.slf4j.Logger; // Import for Logger
import org.slf4j.LoggerFactory; // Import for LoggerFactory

import com.robspecs.Cryptography.Entities.DecryptionKey;
import com.robspecs.Cryptography.Entities.Message;
import com.robspecs.Cryptography.Entities.User;
import com.robspecs.Cryptography.Enums.Algorithm;
import com.robspecs.Cryptography.dto.MessageRequestDTO;
import com.robspecs.Cryptography.factory.EncryptionFactory;
import com.robspecs.Cryptography.repository.DecryptionKeyRepository;
import com.robspecs.Cryptography.repository.MessageRepository;
import com.robspecs.Cryptography.repository.UserRepository;
import com.robspecs.Cryptography.service.MessageService;
import com.robspecs.Cryptography.utils.KeyGenerator;

import jakarta.transaction.Transactional;

@Service
public class MessageServiceImpl implements MessageService {

    private static final Logger log = LoggerFactory.getLogger(MessageServiceImpl.class); // Logger instance

    private final UserRepository userRepo;
    private final MessageRepository messageRepo;
    private final DecryptionKeyRepository keyRepo;
    private final EncryptionFactory factory;
    private final KeyGenerator keyGen;

    public MessageServiceImpl(UserRepository userRepo, MessageRepository messageRepo, DecryptionKeyRepository keyRepo,
                              EncryptionFactory factory, KeyGenerator keyGen) {
        // super(); // This call is redundant and can be omitted in most modern Java constructors
        this.userRepo = userRepo;
        this.messageRepo = messageRepo;
        this.keyRepo = keyRepo;
        this.factory = factory;
        this.keyGen = keyGen;
        log.info("MessageServiceImpl initialized."); // Constructor logging
    }

    @Override
    @Transactional
    public void sendMessage(MessageRequestDTO req, String senderUsername) throws Exception {
        log.info("Attempting to send message from senderUsername: {} to receiverUsername: {} with algorithm: {}",
                 senderUsername, req.getToUsername(), req.getAlgorithm()); // Start method logging

        User sender = userRepo.findByEmailOrUserName(senderUsername)
                .orElseThrow(() -> {
                    log.warn("Sender not found for username: {}", senderUsername); // Specific warning for sender not found
                    return new RuntimeException("Sender not found");
                });
        log.debug("Sender found: {}", sender.getUserName()); // Debug level for found sender

        User receiver = userRepo.findByEmailOrUserName(req.getToUsername())
                .orElseThrow(() -> {
                    log.warn("Receiver not found for username: {}", req.getToUsername()); // Specific warning for receiver not found
                    return new RuntimeException("Receiver not found");
                });
        log.debug("Receiver found: {}", receiver.getUserName()); // Debug level for found receiver

        Algorithm algo = req.getAlgorithm();
        log.debug("Generating key for algorithm: {}", algo); // Debug for key generation

        String key = keyGen.generate(algo);
        // Do NOT log the actual 'key' at info/debug level as it's sensitive decryption info.
        log.debug("Key generated successfully for algorithm: {}", algo); // Confirm key generation

        String encrypted = null; // Initialize to null for try-catch scope
        try {
            encrypted = factory.getEncryptionService(algo).encrypt(req.getRawMessage(), key);
            log.debug("Message successfully encrypted using algorithm: {}", algo); // Debug for successful encryption
        } catch (Exception e) {
            log.error("Error encrypting message with algorithm {}: {}", algo, e.getMessage(), e); // Error logging with exception
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
        log.info("Encrypted message persisted for sender: {} to receiver: {}. Message ID: {}",
                 sender.getUserName(), receiver.getUserName(), msg.getMessageId()); // Info for message persistence

        // Persist DecryptionKey
        DecryptionKey dk = new DecryptionKey();
        dk.setMessage(msg);
        dk.setEncryptedKey(key); // Storing the actual key for decryption later
        keyRepo.save(dk);
        log.info("Decryption key persisted for message ID: {}", msg.getMessageId()); // Info for key persistence

        log.info("Message sending process completed successfully for message ID: {}",msg.getMessageId()); // End method logging
    }
}