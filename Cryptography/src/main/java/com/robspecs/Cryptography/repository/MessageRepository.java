package com.robspecs.Cryptography.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.robspecs.Cryptography.Entities.Message;
import com.robspecs.Cryptography.Entities.User;

@Repository
public interface MessageRepository extends JpaRepository<Message, Long> {
    List<Message> findByReceiver_UserNameOrderByTimestampDesc(String receiverUsername);
    List<Message> findByReceiverOrderByTimestampDesc(User receiver);
    List<Message> findBySenderOrderByTimestampDesc(User sender);

    Optional<Message> findByMessageIdAndReceiver(Long messageId, User receiver);


    @Modifying
    @Query("UPDATE Message m SET m.isRead = :isRead WHERE m.messageId = :messageId AND m.receiver = :receiver")
    void updateIsReadStatus(@Param("messageId") Long messageId, @Param("receiver") User receiver, @Param("isRead") boolean isRead);

    @Modifying
    @Query("UPDATE Message m SET m.isStarred = :isStarred WHERE m.messageId = :messageId AND (m.receiver = :user OR m.sender = :user)")
    void updateIsStarredStatus(@Param("messageId") Long messageId, @Param("user") User user, @Param("isStarred") boolean isStarred);

    // JpaRepository's deleteById or delete(entity) is sufficient for hard delete.
    // If you specifically want to ensure the user is sender/receiver before delete,
    // you'd fetch the message first and then delete it.
    // For a direct delete query with authorization:
    @Modifying
    @Query("DELETE FROM Message m WHERE m.messageId = :messageId AND (m.receiver = :user OR m.sender = :user)")
    void deleteMessageByIdAndUser(@Param("messageId") Long messageId, @Param("user") User user);
}
