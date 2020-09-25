package com.codecool.petproject.modell;

import lombok.*;
import org.springframework.boot.context.properties.bind.DefaultValue;

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


    @ElementCollection(fetch = FetchType.EAGER)
    @Singular
    @Column(name="role")
    @Enumerated(EnumType.STRING)
    private Set<Role> roles;

}
