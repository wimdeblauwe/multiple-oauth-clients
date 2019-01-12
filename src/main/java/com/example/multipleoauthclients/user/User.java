package com.example.multipleoauthclients.user;

import com.fasterxml.jackson.annotation.JsonIgnore;

import java.util.Set;

public class User {
    private long id;
    private String email;
    private String password;
    private Set<UserRole> roles;

    public User(long id, String email, String password, Set<UserRole> roles) {
        this.id = id;
        this.email = email;
        this.password = password;
        this.roles = roles;
    }

    public long getId() {
        return id;
    }

    public String getEmail() {
        return email;
    }

    @JsonIgnore
    public String getPassword() {
        return password;
    }

    public Set<UserRole> getRoles() {
        return roles;
    }
}
