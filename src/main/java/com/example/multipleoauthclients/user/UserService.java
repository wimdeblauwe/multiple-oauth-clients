package com.example.multipleoauthclients.user;

import java.util.Optional;
import java.util.Set;

public interface UserService {
    Set<User> getUsers();

    Optional<User> getByEmail(String email);

    Optional<User> getById(long userId);
}
