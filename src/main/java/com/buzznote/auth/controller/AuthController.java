package com.buzznote.auth.controller;

import com.buzznote.auth.dto.*;
import com.buzznote.auth.models.User;
import com.buzznote.auth.service.AuthService;
import com.buzznote.auth.service.RabbitEmailService;
import com.buzznote.auth.service.RedisService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.apache.commons.validator.routines.EmailValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.Optional;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);
    private final AuthService authService;

    @Autowired
    private RedisService redisService;

    @Autowired
    private RabbitEmailService rabbitEmailService;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request, HttpServletResponse response) {
        LoginResponse loggedInUser = authService.login(request);
        response.addCookie(AuthService.getCookie("refreshToken", loggedInUser.getRefreshToken(), "/api/auth/refresh-token"));
        response.addCookie(AuthService.getCookie("accessToken", loggedInUser.getAccessToken(), "/"));
        return ResponseEntity.status(HttpStatus.OK).body(new AccessToken(loggedInUser.getAccessToken()));
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest user) {
        RegisterResponse response = authService.registerUser(user);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @GetMapping("/user-details")
    public ResponseEntity<?> userDetails(Principal user) {
        if (user == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("UNAUTHORIZED");
        }
        return ResponseEntity.ok().body(user);
    }

    @GetMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(@CookieValue String refreshToken, HttpServletResponse response) {
        LoginResponse refreshed = authService.refreshToken(refreshToken);
        response.addCookie(AuthService.getCookie("accessToken", refreshed.getAccessToken(), "/"));
        response.addCookie(AuthService.getCookie("refreshToken", refreshed.getRefreshToken(), "/api/auth/refresh-token"));
        return ResponseEntity.status(HttpStatus.OK).body(new AccessToken(refreshed.getAccessToken()));
    }

    @GetMapping("/logout")
    public ResponseEntity<?> logout(HttpServletResponse response) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        UserDetails userDetails = (UserDetails) auth.getPrincipal();
        redisService.removeUser(userDetails.getUsername());

        response.addCookie(AuthService.deleteCookie("refreshToken", null, "/api/auth/refresh-token"));
        response.addCookie(AuthService.deleteCookie("accessToken", null, "/"));
        return ResponseEntity.status(200).body("Logged out");
    }

    @PostMapping("/reset-password/init")
    public ResponseEntity<?> resetPasswordInit(@RequestBody PasswordResetInitRequest body) {
        EmailValidator validator = EmailValidator.getInstance();
        if (validator.isValid(body.getEmail())) {
            Optional<User> user = authService.findUserByEmail(body.getEmail());
            if (user.isPresent()) {
                rabbitEmailService.sendPasswordResetEmail(body.getEmail());
                return ResponseEntity.ok().body("Email sent. please check your inbox.");
            }
        }
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Please enter a valid email");
    }

    @PostMapping("/reset-password/validate")
    public ResponseEntity<?> validatePasswordResetToken(@RequestBody PasswordResetValidateRequest body) {
        if (redisService.validatePasswordResetToken(body.getToken())) {
            return ResponseEntity.ok().body(new PasswordResetRequestResponse(body.getToken(), true));
        }
        return ResponseEntity.ok().body(new PasswordResetRequestResponse(body.getToken(), false));
    }

    @PostMapping("/reset-password/complete")
    public ResponseEntity<?> resetPasswordComplete(@RequestBody PasswordResetCompleteRequest body) {
        if (redisService.validatePasswordResetToken(body.getToken())) {
            authService.updateUserPassword(body.getToken(), body.getNewPassword());
        }
        return ResponseEntity.ok().body("Password changed successfully.");
    }
}
