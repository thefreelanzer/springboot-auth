package com.example2.demo.config;

import com.example2.demo.service.JwtService;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * This filter intercepts HTTP requests to authenticate users based on JWT tokens.
 * It runs once per request and verifies the presence and validity of a JWT token in the Authorization header.
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String BEARER_PREFIX = "Bearer ";

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    //private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    /**
     * Constructor to initialize dependencies for JWT validation and user details retrieval.
     *
     * @param jwtService         the service to handle JWT operations.
     * @param userDetailsService the service to load user details.
     */
    public JwtAuthenticationFilter(JwtService jwtService, UserDetailsService userDetailsService) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
    }

    /**
     * Filters incoming HTTP requests and authenticates users if a valid JWT token is present.
     *
     * @param request     the incoming HTTP request.
     * @param response    the outgoing HTTP response.
     * @param filterChain the filter chain for further processing.
     * @throws ServletException in case of servlet-related errors.
     * @throws IOException      in case of I/O errors.
     */
    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        // Retrieve the Authorization header from the request
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;

        // If no Authorization header is present or it doesn't start with "Bearer ", skip authentication
        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            filterChain.doFilter(request, response); // If no token, proceed without authentication
            return;
        }

        // Extract the JWT token from the Authorization header
        jwt = authHeader.substring(BEARER_PREFIX.length());

        try {
            // Extract the username (email) from the JWT token
            userEmail = jwtService.extractUsername(jwt);

            // If a username is found and no authentication is set in the SecurityContext, proceed
            if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {

                // Load user details from the UserDetailsService
                UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);

                // Validate the token against the user details
                if (jwtService.isValidToken(jwt, userDetails)) {
                    // Extract role information for debugging purposes (optional)
                    String role = jwtService.extractClaim(jwt, claims -> claims.get("role", String.class));
                    System.out.println("role extracted from JWT: " + role);

                    // Debug user authorities
                    System.out.println("userDetails.getAuthorities() " + userDetails.getAuthorities());

                    // Create an authentication token with user details and authorities
                    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities()
                    );

                    // Add additional details to the token (e.g., request information)
                    authenticationToken.setDetails(
                            new WebAuthenticationDetailsSource().buildDetails(request)
                    );

                    // Set the authentication in the SecurityContext
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                    System.out.println("User authenticated: " + userDetails.getUsername());
                } else {
                    System.out.println("Invalid JWT token");
                }
            }
        } catch (ExpiredJwtException e) {
            // Handle expired token exceptions
            System.out.println("JWT token expired");
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "JWT token is expired");
        } catch (JwtException e) {
            // Handle generic JWT exceptions
            System.out.println("Invalid JWT token");
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid JWT token");
        } catch (Exception e) {
            // Handle other authentication-related exceptions
            System.out.println("Authentication failed");
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authentication failed");
        }

        // Continue with the next filter in the chain
        filterChain.doFilter(request, response);
    }
}