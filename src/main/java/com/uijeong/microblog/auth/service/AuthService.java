package com.uijeong.microblog.auth.service;

import com.uijeong.microblog.auth.client.MemberClient;
import com.uijeong.microblog.auth.dto.LoginRequest;
import com.uijeong.microblog.auth.dto.TokenResponse;
import com.uijeong.microblog.auth.util.JwtProvider;
import org.springframework.stereotype.Service;

/**
 * 인증 서비스: 사용자 인증 및 토큰 발급
 */
@Service
public class AuthService {

    private final MemberClient memberClient;
    private final JwtProvider jwtProvider;

    public AuthService(MemberClient memberClient, JwtProvider jwtProvider) {
        this.memberClient = memberClient;
        this.jwtProvider = jwtProvider;
    }

    /**
     * 로그인
     *
     * @param request 로그인 요청
     * @return JWT 토큰 응답 DTO
     */
    public TokenResponse login(LoginRequest request) {
        var member = memberClient.findByEmail(request.email());

        if (!member.password().equals(request.password())) {
            throw new IllegalArgumentException("비밀번호 불일치");
        }

        String token = jwtProvider.generateToken(member.id(), member.nickname(), member.role());
        return new TokenResponse(token);
    }
}
