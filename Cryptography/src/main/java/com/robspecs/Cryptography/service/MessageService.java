package com.robspecs.Cryptography.service;

import com.robspecs.Cryptography.dto.MessageRequestDTO;

public interface MessageService {
    void sendMessage(MessageRequestDTO request, String senderUsername) throws Exception;
}
