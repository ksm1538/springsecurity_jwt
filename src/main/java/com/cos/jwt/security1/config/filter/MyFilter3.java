package com.cos.jwt.security1.config.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter3 implements Filter {

    // 토큰 값을 확인하는 필터
    // 토큰 생성 시점: 정상적으로 로그인 시, 토큰을 만들어주고 토큰을 알려줌 => 사용자가 요청할 때마다 header에 Authorization에 value값으로 토큰을 가지고 요청 => 그 때 토큰이 유효한 지 검증하는 로직
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;
        System.out.println("filter3");

        // POST 요청일 때만 확인
        if(req.getMethod().equals("POST")){


            String headerAuth = req.getHeader("Authorization");     // Header의 name이 'Authorization' 인 value
            System.out.println(headerAuth);

            if(headerAuth != null && headerAuth.equals("cos")){     // Authorization이 'cos' 면 토큰을 가지고 있는 것으로 간주
                chain.doFilter(req,res);
            }
            else{           // 아니라면 인증이 안 된것
                PrintWriter outPrintWriter = res.getWriter();
                outPrintWriter.println("인증X");
            }
        }
    }
}
