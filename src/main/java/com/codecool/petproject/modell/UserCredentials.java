package com.codecool.petproject.modell;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class UserCredentials {


    private String username;
    private String email;
    private String password;

}
