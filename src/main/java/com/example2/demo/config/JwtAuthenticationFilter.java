package com.example2.demo.config;

import com.example2.demo.service.JwtService;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.NonNull;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.stream.Collectors;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String BEARER_PREFIX = "Bearer ";

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    //private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    public JwtAuthenticationFilter(JwtService jwtService, UserDetailsService userDetailsService) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;

        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            filterChain.doFilter(request, response); // If no token, proceed without authentication
            return;
        }

        jwt = authHeader.substring(BEARER_PREFIX.length());

        try {
            userEmail = jwtService.extractUsername(jwt);

            if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);

                if (jwtService.isValidToken(jwt, userDetails)) {
                    String role = jwtService.extractClaim(jwt, claims -> claims.get("role", String.class));
                    System.out.println("role extracted from JWT: " + role);

                    System.out.println("userDetails.getAuthorities() " + userDetails.getAuthorities());

                    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities()
                    );
                    authenticationToken.setDetails(
                            new WebAuthenticationDetailsSource().buildDetails(request)
                    );

                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                    System.out.println("User authenticated: {}" +  userDetails.getUsername());
                } else {
                    System.out.println("Invalid JWT token");
                }
            }
        } catch (ExpiredJwtException e) {
            System.out.println("JWT token expired");
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "JWT token is expired");
        } catch (JwtException e) {
            System.out.println("Invalid JWT token");
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid JWT token");
        } catch (Exception e) {
            System.out.println("Authentication failed");
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authentication failed");
        }

        filterChain.doFilter(request, response);
    }
}