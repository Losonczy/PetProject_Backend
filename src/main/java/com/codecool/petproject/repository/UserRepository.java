package com.codecool.petproject.repository;

import com.codecool.petproject.modell.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {
}
