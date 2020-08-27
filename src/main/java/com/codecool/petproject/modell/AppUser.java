package com.codecool.petproject.modell;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import javax.validation.constraints.NotBlank;
import java.util.Set;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Table(name="users")
public class AppUser {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(name="username")
    private String userName;

    @NotBlank
    @Column(name="password")
    private String hashedPassword;

    @Column(name="email")
    private String email;

    @Column(name="role")
    @Enumerated(EnumType.STRING)
    private String roles;

}
