package com.buzznote.auth.service;

import com.buzznote.auth.dto.LoginRequest;
import com.buzznote.auth.dto.LoginResponse;
import com.buzznote.auth.dto.RegisterRequest;
import com.buzznote.auth.dto.RegisterResponse;
import com.buzznote.auth.exception.InvalidCredentialsException;
import com.buzznote.auth.models.User;
import com.buzznote.auth.repo.UserRepo;
import jakarta.servlet.http.Cookie;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthService {
    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    private final UserRepo userRepo;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    @Autowired
    private RedisService redisService;

    public static Cookie getCookie(String key, String value, String path) {
        Cookie cookie = new Cookie(key, value);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath(path);
        cookie.setMaxAge(7 * 24 * 60 * 60);
        return cookie;
    }

    public static Cookie deleteCookie(String key, String value, String path) {
        Cookie cookie = new Cookie(key, value);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath(path);
        cookie.setMaxAge(0);
        return cookie;
    }

    public LoginResponse login(LoginRequest request) {
        try {
            Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));
            if (!authentication.isAuthenticated()) {
                throw new InvalidCredentialsException();
            }

            User fetchedUser = findUserByEmail(request.getEmail()).orElseThrow(() -> new UsernameNotFoundException("User not found"));
            String accessToken = jwtService.createAccessToken(fetchedUser);
            String refreshToken = jwtService.createRefreshToken(fetchedUser);

            redisService.setAccessToken(fetchedUser.getEmail(), accessToken);
            redisService.setRefreshToken(fetchedUser.getEmail(), refreshToken);

            LoginResponse response = new LoginResponse();
            response.setAccessToken(accessToken);
            response.setRefreshToken(refreshToken);
            logger.info("Login success: {}", fetchedUser.getEmail());
            return response;

        } catch (InvalidCredentialsException | BadCredentialsException e) {
            logger.info("Login failed: {} -> {}", request.getEmail(), e.getMessage());
            throw new InvalidCredentialsException();
        }
    }

    public RegisterResponse registerUser(RegisterRequest user) {
        User newUser = new User();
        newUser.setEmail(user.getEmail());
        newUser.setPassword(passwordEncoder.encode(user.getPassword()));

        User u = userRepo.save(newUser);
        return new RegisterResponse(u.getEmail());
    }

    public Optional<User> findUserByEmail(String email) {
        return userRepo.findByEmail(email);
    }

    public void updateUserPassword(String token, String newPassword) {
        User user = userRepo.findByEmail(redisService.getPasswordResetUserEmail(token)).orElseThrow(() -> new UsernameNotFoundException("User not found"));
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepo.save(user);
    }

    public LoginResponse refreshToken(String refreshToken) {
        User user = findUserByEmail(jwtService.extractUsername(refreshToken)).orElseThrow(() -> new UsernameNotFoundException("User not found"));

        try {
            if (jwtService.validateRefreshToken(refreshToken)) {
                if (redisService.isValidRefreshToken(user.getEmail(), refreshToken)) {
                    String newRefreshToken = jwtService.createRefreshToken(user);
                    String newAccessToken = jwtService.createAccessToken(user);

                    redisService.setAccessToken(user.getEmail(), newAccessToken);
                    redisService.setRefreshToken(user.getEmail(), newRefreshToken);
                    logger.info("Token refresh successful: {}", user.getEmail());
                    return new LoginResponse(newAccessToken, newRefreshToken);
                }
            }
            logger.info("Invalid refresh token from: {}", user.getEmail());
            throw new InvalidCredentialsException();
        } catch (InvalidCredentialsException e) {
            throw new InvalidCredentialsException("Invalid or expired token. please sign in again");
        }
    }
}
