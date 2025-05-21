package com.robspecs.Cryptography.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.robspecs.Cryptography.Entities.DecryptionKey;

public interface DecryptionKeyRepository extends JpaRepository<DecryptionKey, Long> {
    Optional<DecryptionKey> findByMessage_MessageId(Long messageId);
}