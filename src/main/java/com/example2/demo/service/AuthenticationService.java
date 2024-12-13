package com.example2.demo.service;

import com.example2.demo.controller.auth.AuthenticateRequest;
import com.example2.demo.controller.auth.AuthenticationResponse;
import com.example2.demo.controller.auth.RegisterRequest;
import com.example2.demo.entity.Role;
import com.example2.demo.entity.User;
import com.example2.demo.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    // Dependencies injected through constructor
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    /**
     * Handles user registration by creating a new user, encoding their password,
     * assigning a default role, and generating a JWT token.
     *
     * @param request contains registration details like first name, last name, email, and password
     * @return AuthenticationResponse containing the generated JWT token
     */
    public AuthenticationResponse register(RegisterRequest request) {

        // Create and populate a new User entity
        var user = new User();
        user.setFirstname(request.getFirstname());
        user.setLastname(request.getLastname());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRole(Role.USER);

        userRepository.save(user);
        var jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }

    /**
     * Handles user authentication by validating their credentials and generating a JWT token.
     *
     * @param request contains login credentials (email and password)
     * @return AuthenticationResponse containing the generated JWT token
     */
    public AuthenticationResponse authenticate(AuthenticateRequest request) {

        // Authenticate the user using the authentication manager
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));

        // Fetch the user from the database
        var user = userRepository.findByEmail(request.getEmail()).orElseThrow();

        // Generate JWT token for the authenticated user
        var jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }
}
