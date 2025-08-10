package com.uijeong.microblog.auth.filter;

import com.uijeong.microblog.auth.util.JwtProvider;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtProvider jwtProvider;

    @Override
    protected void doFilterInternal(
        HttpServletRequest request,
        HttpServletResponse response,
        FilterChain filterChain
    ) throws ServletException, IOException {
        // Authorization 헤더에서 JWT 추출
        String token = jwtProvider.resolveToken(request);

        // 토큰 유효성 검사
        if (token != null && jwtProvider.validateToken(token)) {
            // 유저 정보로 인증 객체 생성
            Authentication authentication = jwtProvider.getAuthentication(token);
            // SecurityContext 에 인증 정보 저장
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        // 다음 필터로 진행
        filterChain.doFilter(request, response);
    }
}
