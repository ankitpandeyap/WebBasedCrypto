package com.robspecs.Cryptography.service;

import java.util.List;

import com.robspecs.Cryptography.Entities.User;
import com.robspecs.Cryptography.dto.MessageRequestDTO;
import com.robspecs.Cryptography.dto.MessageSummaryDTO;

public interface MessageService {
    void sendMessage(MessageRequestDTO request, String senderUsername) throws Exception;
    public List<MessageSummaryDTO> getInboxMessages(User receiver);
    String decryptMessage(Long messageId, User currentUser, String passkey) throws Exception;
    public String verifyPasskeyAndGetKey(Long messageId, User currentUser, String passkey) throws Exception;
    List<MessageSummaryDTO> getSentMessages(User sender);
    public void markMessageAsRead(Long messageId, String currentUsername);
    void toggleMessageStarred(Long messageId, String currentUsername);
    void deleteMessage(Long messageId, String currentUsername);
}
