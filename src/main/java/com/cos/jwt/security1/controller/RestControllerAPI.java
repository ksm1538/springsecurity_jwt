package com.cos.jwt.security1.controller;

import com.cos.jwt.security1.Repository.UserRepository;
import com.cos.jwt.security1.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
public class RestControllerAPI {
    @Autowired
    UserRepository userRepository;

    @Autowired
    BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping("home")
    public String Home(){
        return "<h1>home</h1>";
    }

    @PostMapping("token")
    public String Token(){
        return "<h1>token</h1>";
    }

    @GetMapping("admin/users")
    public List<User> users(){
        return userRepository.findAll();
    }

    @PostMapping("register")
    public String join(@RequestBody User user){
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        user.setRole("ROLE_USER");
        userRepository.save(user);

        return "회원가입 완료";
    }
}
