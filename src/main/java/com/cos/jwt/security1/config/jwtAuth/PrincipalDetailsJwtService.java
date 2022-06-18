package com.cos.jwt.security1.config.jwtAuth;


import com.cos.jwt.security1.Repository.UserRepository;
import com.cos.jwt.security1.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;


@Service
@RequiredArgsConstructor
public class PrincipalDetailsJwtService implements UserDetailsService {

    private final UserRepository userRepository;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("jwtAuth.PrincipalDetailsService.loadUserByUsername");

        // **** 로그인 과정 **** //
        // 1. username과 password를 받고

        // 2. 정상인지 확인. authentcationManager로 로그인 시도를 하면 PrincipalDetailsJwtService의 loadUserByUsername이 실행됨

        // 3. PrincipalDetails를 세션에 담고(권한 관리를 위해서. 권한같은 정보가 없다면 세션이 필요없음)

        // 4. JWT 토큰을 만들고 응답

        User userEntity = userRepository.findByUsername(username);
        System.out.println("찾은 UserEntity : " + userEntity.toString());
        PrincipalDetails p = new PrincipalDetails(userEntity);

        return p;
    }
}
