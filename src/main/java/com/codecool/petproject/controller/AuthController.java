package com.codecool.petproject.controller;


import com.codecool.petproject.modell.AppUser;
import com.codecool.petproject.modell.UserCredentials;
import com.codecool.petproject.repository.AppUserRepository;
import com.codecool.petproject.security.JwtUtil;
import com.codecool.petproject.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletResponse;

@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final UserService userService;
    @Autowired
    AppUserRepository  appUserRepository;

    @PostMapping("/login")
    public ResponseEntity<AppUser> login (@RequestBody UserCredentials appUser, HttpServletResponse response){
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
             appUser.getEmail(),
             appUser
        ))
    }


}
