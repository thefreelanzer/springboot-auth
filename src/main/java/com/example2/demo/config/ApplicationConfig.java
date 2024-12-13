package com.example2.demo.config;

import com.example2.demo.repository.UserRepository;
import com.example2.demo.service.CustomUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * This configuration class sets up beans for application security, including
 * user authentication and password encoding.
 */
@Configuration
public class ApplicationConfig {

    private final UserRepository userRepository;
    private final CustomUserDetailsService customUserDetailsService;

    /**
     * Constructor-based dependency injection for UserRepository and CustomUserDetailsService.
     *
     * @param userRepository           the repository to interact with user data.
     * @param customUserDetailsService custom implementation of UserDetailsService.
     */
    public ApplicationConfig(UserRepository userRepository, CustomUserDetailsService customUserDetailsService) {
        this.userRepository = userRepository;
        this.customUserDetailsService = customUserDetailsService;
    }

    /**
     * Configures a UserDetailsService bean that fetches user details from the UserRepository.
     *
     * @return a lambda-based UserDetailsService implementation.
     */
    @Bean
    public UserDetailsService userDetailsService() {
        return username -> userRepository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found!"));

    }

    /**
     * Configures an AuthenticationProvider bean using DaoAuthenticationProvider.
     *
     * @return a fully configured DaoAuthenticationProvider.
     */
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        //authProvider.setUserDetailsService(userDetailsService());
        authProvider.setUserDetailsService(customUserDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    /**
     * Configures an AuthenticationManager bean using the AuthenticationConfiguration.
     *
     * @param configuration the AuthenticationConfiguration provided by Spring.
     * @return a configured AuthenticationManager instance.
     * @throws Exception if an error occurs while getting the AuthenticationManager.
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    /**
     * Configures a PasswordEncoder bean using BCryptPasswordEncoder.
     *
     * @return a BCryptPasswordEncoder instance with the default strength.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
