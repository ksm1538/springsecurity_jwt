package com.cos.jwt.security1.config.jwtConfig;


import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.security1.config.jwtAuth.PrincipalDetails;
import com.cos.jwt.security1.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

// spring security에서 UsernamePasswordAuthenticationFilter 가 있는데
// login 요청 시, username, pw 전송 시, UsernamePasswordAuthenticationFilter가 동작함

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    // /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter.attemptAuthentication : 로그인 시도중입니다");

        try{
            // 1. usernamee, pw 받기

            // request로 부터 온 데이터들 확인 방법
            /*
            BufferedReader br = request.getReader();

            String input = null;
            while(true){
                input = br.readLine();
                if(input == null){
                    break;
                }
                System.out.println(input);
            }
            */

            // request로 부터 온 데이터(JSON으로 보냈다는 가정 하에) 를 JSON 형태로 변환하기
            ObjectMapper objectMapper = new ObjectMapper();
            User user = objectMapper.readValue(request.getInputStream(), User.class);
            System.out.println(user.toString());
            System.out.println("========================================1");


            // 토큰 생성 (폼 로그인 시에는 자동으로 해줌)
            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
            System.out.println("========================================2");


            // PrincipalDetailsJwtService의 loadUserByUsername() 함수가 실행됨
            Authentication authentication =  authenticationManager.authenticate(authenticationToken);
            System.out.println("========================================3");


            // 로그인을 성공했다는 뜻
            PrincipalDetails principal = (PrincipalDetails) authentication.getPrincipal();
            System.out.println("로그인 한 사용자 : " + principal.getUser().getUsername());
            System.out.println("========================================4");

            // authentication 객체가 session 영역에 저장
            // 리턴하는 이유는 권한 관리를 security가 대신 해주기 때문에 편하기 위해서.
            // JWT 토큰을 사용한다면 세션을 사용할 필요가 없지만 권한 관리 때문에 세션을 사용하는 것
            return authentication;
        } catch(IOException e){
            e.printStackTrace();
        }

        return null;
    }

    // attemptAuthentication 실행 후 인증이 정상적으로 완료되면 successfulAuthentication 함수가 실행됨
    // JWT 토큰을 만들어서 request 요청한 사용자에게 JWT 토큰을 주면 된다.
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();
        // JWT 토큰 만들기
        // RSA 방식이 아닌, Hash암호방식 (최근 이 방식을 더 많이 사용한다고 함)
        String jwtToken  = JWT.create()
                .withSubject("토큰 제목")       // 토큰 제목
                .withExpiresAt(new Date(System.currentTimeMillis()+(60000*10)))      // 토큰 만료시간 ms 기준 60초 * 10 (10분)
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512("cos"));

        response.addHeader("Authentication", "Bearer " + jwtToken);
    }
}
