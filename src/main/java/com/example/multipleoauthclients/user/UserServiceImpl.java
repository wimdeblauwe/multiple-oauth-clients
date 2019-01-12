package com.example.multipleoauthclients.user;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@Service
public class UserServiceImpl implements UserService {

    private final Set<User> users = new HashSet<>();

    public UserServiceImpl(PasswordEncoder passwordEncoder) {
        users.add(new User(1, "player@example.com",
                           passwordEncoder.encode("pwd-player"),
                           new HashSet<>(Arrays.asList(UserRole.USER, UserRole.PLAYER))));
        users.add(new User(2, "admin@example.com",
                           passwordEncoder.encode("pwd-admin"),
                           new HashSet<>(Arrays.asList(UserRole.USER, UserRole.ADMINISTRATOR))));
    }

    @Override
    public Set<User> getUsers() {
        return users;
    }

    @Override
    public Optional<User> getByEmail(String email) {
        return users.stream()
                    .filter(user -> user.getEmail().equals(email))
                    .findFirst();
    }

    @Override
    public Optional<User> getById(long userId) {
        return users.stream()
                    .filter(user -> user.getId() == userId)
                    .findFirst();
    }
}
