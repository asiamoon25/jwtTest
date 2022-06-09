package me.yeonsang.jwttest.controller;

import lombok.RequiredArgsConstructor;
import me.yeonsang.jwttest.config.security.JwtTokenProvider;
import me.yeonsang.jwttest.domain.User;
import me.yeonsang.jwttest.domain.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.Map;

@RequiredArgsConstructor
@RestController
public class UserController {

    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final UserRepository userRepository;

    @PostMapping("/join")
    public Long join(@RequestBody Map<String,String> user) {
        return userRepository.save(User.builder()
                .email(user.get("email"))
                .password(passwordEncoder.encode(user.get("password")))
                .roles(Collections.singletonList("ROLE_USER"))
                .build()).getId();

    }

    @PostMapping("/login")
    public String login(@RequestBody Map<String,String>user){
        User member = userRepository.findByEmail(user.get("email"))
                .orElseThrow(()-> new IllegalArgumentException("가입되지 않은 Email"));
        if(!passwordEncoder.matches(user.get("password"), member.getPassword())) {
            throw new IllegalArgumentException("잘못된 비밀번호");
        }
        return jwtTokenProvider.createToken(member.getUsername(), member.getRoles());
    }
}
