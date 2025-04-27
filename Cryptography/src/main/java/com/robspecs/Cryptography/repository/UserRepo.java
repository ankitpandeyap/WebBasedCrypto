package com.robspecs.Cryptography.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.robspecs.Cryptography.Entities.CustomUser;

@Repository
public interface UserRepo extends JpaRepository<CustomUser, Long> {

}
