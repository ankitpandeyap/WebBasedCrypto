package com.robspecs.Cryptography.service;

import java.util.List;

import com.robspecs.Cryptography.Entities.User;
import com.robspecs.Cryptography.dto.MessageRequestDTO;
import com.robspecs.Cryptography.dto.MessageSummaryDTO;
import com.robspecs.Cryptography.dto.FileDownloadResponseDTO; // NEW IMPORT: Import your new DTO

// Removed duplicate import: import org.springframework.core.io.ByteArrayResource;

public interface MessageService {
    void sendMessage(MessageRequestDTO request, String senderUsername) throws Exception;

    // --- NEW METHOD FOR FILE UPLOAD (FOR STEP 8) ---
    // This method will handle the logic for encrypting and saving a file message.
    void sendFile(MessageRequestDTO request, String senderUsername) throws Exception;
    // --- END NEW METHOD ---

    public List<MessageSummaryDTO> getInboxMessages(User receiver);

    // --- UPDATED METHOD: downloadFile (FOR STEP 12) ---
    // This method will retrieve and decrypt a file, returning it as a resource
    // along with its filename and content type using the new DTO.
    FileDownloadResponseDTO downloadFile(Long messageId, User currentUser, String passkey) throws Exception;
    // --- END UPDATED METHOD ---

    String decryptMessage(Long messageId, User currentUser, String passkey) throws Exception;

    public String verifyPasskeyAndGetKey(Long messageId, User currentUser, String passkey) throws Exception;

    List<MessageSummaryDTO> getSentMessages(User sender);

    public void markMessageAsRead(Long messageId, String currentUsername);

    void toggleMessageStarred(Long messageId, String currentUsername);

    void deleteMessage(Long messageId, String currentUsername);

    // Removed getMessageRepository() if it was present, as it's no longer needed in the service contract
    // since the downloadFile method will now provide all necessary info directly.
}