package com.codecool.petproject.service;


import com.codecool.petproject.modell.UserCredentials;
import com.codecool.petproject.modell.AppUser;
import com.codecool.petproject.modell.Role;
import com.codecool.petproject.repository.AppUserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collections;


@Service
@RequiredArgsConstructor
public class UserService {

    private final AppUserRepository appUserRepository;
    private final PasswordEncoder encoder;

    public AppUser register (String username, String password, Role role, String email) {
        return appUserRepository.save(
                AppUser.builder()
                        .userName(username)
                        .hashedPassword(encoder.encode(password))
                        .roles(Collections.singleton(Role.USER))
                        .email(email)
                        .build()
        );
    }

    public AppUser registerr(String username, String password) {
        return appUserRepository.save(
                AppUser.builder()
                        .userName(username)
                        .hashedPassword(encoder.encode(password))
                        .roles(Collections.singleton(Role.USER))
                        .build()
        );
    }

    public AppUser register (UserCredentials userCredentials) {
        return registerr(userCredentials.getUsername(), userCredentials.getPassword());
    }
}
