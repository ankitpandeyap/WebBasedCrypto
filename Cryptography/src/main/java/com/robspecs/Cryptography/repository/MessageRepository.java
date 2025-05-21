package com.robspecs.Cryptography.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.robspecs.Cryptography.Entities.Message;

public interface MessageRepository extends JpaRepository<Message, Long> {
    List<Message> findByReceiver_UserNameOrderByTimestampDesc(String receiverUsername);
}
