package com.robspecs.Cryptography.service;

import java.util.List;

import com.robspecs.Cryptography.Entities.User;
import com.robspecs.Cryptography.dto.MessageRequestDTO;
import com.robspecs.Cryptography.dto.MessageSummaryDTO;

public interface MessageService {
    void sendMessage(MessageRequestDTO request, String senderUsername) throws Exception;
    public List<MessageSummaryDTO> getInboxMessages(User receiver);
}
