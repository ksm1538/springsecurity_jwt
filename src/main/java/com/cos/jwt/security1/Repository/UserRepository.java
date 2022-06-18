package com.cos.jwt.security1.Repository;

import com.cos.jwt.security1.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

// CRUD 로직을 JpaRepository가 들고있음
// 참고로, @Repository가 없어도 됨. (JpaRepository를 상속받아서)
public interface UserRepository extends JpaRepository<User, Long> {

    User findByUsername(String username);


}
