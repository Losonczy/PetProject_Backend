package com.codecool.petproject.modell;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class SignupCredentials {

    String username;
    String password;
    Role role;


}
