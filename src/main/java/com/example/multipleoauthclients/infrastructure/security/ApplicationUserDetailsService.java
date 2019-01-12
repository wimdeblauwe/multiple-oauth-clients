package com.example.multipleoauthclients.infrastructure.security;

import com.example.multipleoauthclients.user.User;
import com.example.multipleoauthclients.user.UserService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class ApplicationUserDetailsService implements UserDetailsService {

    private final UserService userService;

    public ApplicationUserDetailsService(UserService userService) {
        this.userService = userService;
    }

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        User user = userService.getByEmail(s)
                               .orElseThrow(() -> new UsernameNotFoundException(s));
        return new ApplicationUserDetails(user);
    }
}
