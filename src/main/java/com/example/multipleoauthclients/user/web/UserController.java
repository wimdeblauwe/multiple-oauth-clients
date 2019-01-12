package com.example.multipleoauthclients.user.web;

import com.example.multipleoauthclients.infrastructure.security.ApplicationUserDetails;
import com.example.multipleoauthclients.user.User;
import com.example.multipleoauthclients.user.UserService;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/api/users/me")
    public User getMe(@AuthenticationPrincipal ApplicationUserDetails userDetails) {
        return userService.getById(userDetails.getUserId())
                          .orElseThrow(() -> new RuntimeException("User not found"));
    }
}
