package com.codecool.petproject.repository;

import com.codecool.petproject.modell.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AppUserRepository extends JpaRepository<AppUser, Long> {
    AppUser findByUserName(String username);
    AppUser findByEmail(String email);
}
