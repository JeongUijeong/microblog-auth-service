package com.uijeong.microblog.auth.service;

import com.uijeong.microblog.auth.client.MemberClient;
import com.uijeong.microblog.auth.dto.LoginRequest;
import com.uijeong.microblog.auth.dto.MemberResponse;
import com.uijeong.microblog.auth.dto.TokenResponse;
import com.uijeong.microblog.auth.entity.RefreshToken;
import com.uijeong.microblog.auth.repository.RefreshTokenRepository;
import com.uijeong.microblog.auth.util.JwtProvider;
import io.jsonwebtoken.Claims;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

/**
 * 인증/인가 서비스
 */
@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final JwtProvider jwtProvider;
    private final RefreshTokenRepository refreshTokenRepository;
    private final MemberClient memberClient; // 로그인시 member 정보 확인 (optional)

    /**
     * 로그인 서비스: 인증, 토큰 생성 & 저장
     */
    public TokenResponse login(LoginRequest req) {
        // Spring Security 인증 수행(Password 비교 포함)
        var auth = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(req.email(), req.password())
        );

        // 인증 성공 -> User 식별
        String subject = auth.getName(); // 보통 email
        List<String> roles = auth.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .toList();

        // Access Token 생성
        String accessToken = jwtProvider.generateAccessToken(subject, roles);

        // Refresh Token 생성 (jti 생성 후 DB 저장)
        String jti = UUID.randomUUID().toString(); // refresh 토큰 고유 ID
        String refreshToken = jwtProvider.generateRefreshToken(subject, jti);

        // DB에 저장 (expiry는 token 내부 만료와 동일하게 저장)
        Claims refreshClaims = jwtProvider.parseClaims(refreshToken);
        Instant expiry = refreshClaims.getExpiration().toInstant();
        MemberResponse member = memberClient.findByEmail(subject);
        refreshTokenRepository.save(new RefreshToken(jti, member.id(), expiry));

        return new TokenResponse(accessToken, refreshToken);
    }

    /**
     * Token 재발급 서비스: Refresh token으로 access token 재발급(토큰 회전)
     */
    public TokenResponse refreshAccessToken(String refreshToken) {
        // signature/expiry 검사
        if (!jwtProvider.validateToken(refreshToken)) {
            throw new IllegalArgumentException("Invalid refresh token");
        }

        // jti 추출 -> DB에 존재하는지 확인
        String jti = jwtProvider.getJti(refreshToken);
        Optional<RefreshToken> opt = refreshTokenRepository.findById(jti);
        if (opt.isEmpty()) {
            throw new IllegalArgumentException("Refresh token not found / revoked");
        }

        RefreshToken stored = opt.get();
        if (stored.getExpiryDate().isBefore(Instant.now())) {
            // 만료된 경우 DB에서 제거 후 실패
            refreshTokenRepository.deleteById(jti);
            throw new IllegalArgumentException("Refresh token expired");
        }

        // 발급 주체(subject) 얻기
        String subject = jwtProvider.getSubject(refreshToken);

        // 새 access, 새 refresh 생성 (rotate)
        // 삭제(회전) - 기존 refresh는 즉시 무효화
        refreshTokenRepository.deleteById(jti);

        String newJti = UUID.randomUUID().toString();
        String newRefresh = jwtProvider.generateRefreshToken(subject, newJti);
        Claims newRefreshClaims = jwtProvider.parseClaims(newRefresh);
        refreshTokenRepository.save(new RefreshToken(newJti, stored.getUserId(),
            newRefreshClaims.getExpiration().toInstant()));

        // 역할을 refresh 토큰에 별도 포함하지 않아 DB 또는 member-service에서 역할을 다시 조회해야 함.
        MemberResponse member = memberClient.findByEmail(subject);
        List<String> roles = member.roles();
        String newAccess = jwtProvider.generateAccessToken(subject, roles);

        return new TokenResponse(newAccess, newRefresh);
    }

    /**
     * 로그아웃 서비스: refresh 토큰 무효화
     */
    public void logout(String refreshToken) {
        if (!jwtProvider.validateToken(refreshToken)) {
            return;
        }
        String jti = jwtProvider.getJti(refreshToken);
        refreshTokenRepository.deleteById(jti);
    }
}
