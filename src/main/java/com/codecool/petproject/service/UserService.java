package com.codecool.petproject.service;

import com.codecool.petproject.modell.AppUser;
import com.codecool.petproject.modell.Role;
import com.codecool.petproject.repository.AppUserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;


@Service
@RequiredArgsConstructor
public class UserService {

    private final AppUserRepository appUserRepository;
    private final PasswordEncoder encoder;

    public AppUser register(String username, String password, String email) {
        return appUserRepository.save(
                AppUser.builder()
                        .userName(username)
                        .hashedPassword(encoder.encode(password))
                        .email(email)
                        .role.(Role.USER)
                        .build()
        );
    }
}
