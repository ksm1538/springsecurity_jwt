package com.cos.jwt.security1.config;

import com.cos.jwt.security1.Repository.UserRepository;
import com.cos.jwt.security1.config.filter.MyFilter3;
import com.cos.jwt.security1.config.jwtConfig.JwtAuthenticationFilter;
import com.cos.jwt.security1.config.jwtConfig.JwtAuthorizationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.filter.CorsFilter;


@Configuration
@EnableWebSecurity      // spring security filter가 Spring filter chain 에 등록
// securedEnabled: @Secured 어노테이션 활성화. @Secured? 특정 URL에 대해서만 간단하게 권한 처리를 할 수 있는 어노테이션
// prePostEnabled: @PreAuthorize, @PostAuthorize 어노테이션 활성화.
// @PreAuthorize: 해당 메소드 진입 전 처리. @PostAuthorize: 해당 메소드 진입 후 처리
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private final CorsFilter corsFilter;

    private final UserRepository userRepository;
    /**
     * password 암호화
     * @return
     */
    @Bean
    public BCryptPasswordEncoder encodePw(){
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception{       // Spring Security 설정
        http.csrf().disable();      // csrf 비활성화

        /********* JWT 관련 설정 부분(시작) ******/
        // Spring Security 기본 로그인 및 OAuth2를 사용하기 위해서는 아래의 설정 주석 처리 필요
        ///*

        //http.addFilterBefore(new MyFilter3(), BasicAuthenticationFilter.class);     // BasicAuthenticationFilter 이전에 MyFilter3을 추가하겠다.
        // 시큐리티 필터가 커스텀 필터보다 먼저 실행됨

        // 커스텀 필터를 시큐리티 필터보다 먼저 실행시키는 방법
        // 시큐리티 필터 중, 가장 먼저 실행되는 필터는 SecurityContextPersistenceFilter 이므로 이것보다 앞에 위치하면 됨.0
        //http.addFilterBefore(new MyFilter1(), SecurityContextPersistenceFilter.class);

        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)         // 세션을 사용하지 않겠다라는 의미
                        .and()
                        .addFilter(corsFilter)              // 인증이 있어야할 때 시큐리티 필터에 등록. (인증이 필요없을 때 해당 컨트롤러에 @CrossOrigin 어노테이션을 사용하면 됨)
                        .formLogin().disable()              // Spring Security 로그인 사용 X
                        .httpBasic().disable()              // http를 제외한 다른 방식(js로 요청 등)을 허용하겠다.
                        .addFilter(new JwtAuthenticationFilter(authenticationManager()))       // JWtAuthenticationFilter 추가. (로그인 기능을 비활성화해서 로그인 기능을 가진 커스텀 필터를 직접 넣어줌), authenticationManager()은 WebSecurityConfigurerAdapter이 가지고 있음
                        .addFilter(new JwtAuthorizationFilter(authenticationManager(), userRepository))       // JwtAuthorizationFilter 추가. (권한이나 인증이 필요한 주소 요청 시의 필터)
                        .authorizeRequests()
                        .antMatchers("/api/v1/user/**")
                        .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                        .antMatchers("/api/v1/manager/**")
                        .access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                        .antMatchers("/api/v1/admin/**")
                        .access("hasRole('ROLE_ADMIN')")
                        .anyRequest().permitAll();

    }
}
