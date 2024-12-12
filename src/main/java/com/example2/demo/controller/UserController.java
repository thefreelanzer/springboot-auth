package com.example2.demo.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/users")
public class UserController {

    @GetMapping("/user/check")
    public ResponseEntity<String> userAccess() {
        return ResponseEntity.ok("Welcome, USER! You have user-level access.");
    }

    @GetMapping("/admin/check")
    public ResponseEntity<String> adminAccess() {
        return ResponseEntity.ok("Welcome, ADMIN! You have admin-level access.");
    }
}
