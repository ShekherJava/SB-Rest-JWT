package com.example.demo.service;

import java.util.List;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final JdbcTemplate jdbcTemplate;

    public CustomUserDetailsService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // Load user details from the 'users' table
        UserDetails user = jdbcTemplate.queryForObject(
                "SELECT username, password, enabled FROM users WHERE username = ?",
                (rs, rowNum) -> User.withUsername(rs.getString("username"))
                        .password(rs.getString("password"))
                        .authorities(getAuthorities(username)) // Set authorities
                        .accountExpired(false)
                        .accountLocked(false)
                        .credentialsExpired(false)
                        .disabled(!rs.getBoolean("enabled"))
                        .build(),
                username
        );

        if (user == null) {
            throw new UsernameNotFoundException("User not found: " + username);
        }
        return user;
    }

    // Helper method to load user authorities from the 'authorities' table
    private List<GrantedAuthority> getAuthorities(String username) {
        return jdbcTemplate.query(
                "SELECT authority FROM authorities WHERE username = ?",
                (rs, rowNum) -> new SimpleGrantedAuthority(rs.getString("authority")),
                username
        );
    }
}
