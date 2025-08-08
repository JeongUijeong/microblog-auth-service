package com.uijeong.microblog.auth.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import java.security.Key;
import java.util.Date;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * JWT 생성 유틸 클래스
 */
@Slf4j
@Component
public class JwtProvider {

    // yml에서 주입받은 secret 값을 저장할 변수
    @Value("${jwt.secret}")
    private String secretKey;

    // JWT 토큰의 유효 기간
    private static final long TOKEN_VALIDITY = 1000 * 60 * 60;

    // 암호화 키 객체
    private Key key;

    // Bean 생성 후, 시크릿 키를 기반으로 Key 객체 초기화
    @PostConstruct
    public void init() {
        this.key = Keys.hmacShaKeyFor(secretKey.getBytes());
    }

    /**
     * 사용자 ID를 기반으로 JWT 토큰 생성
     * @param memberId 사용자 식별자
     * @param role 사용자 역할
     * @return JWT 문자열
     */
    public String generateToken(Long memberId, String nickname, String role) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + TOKEN_VALIDITY * 1000);

        return Jwts.builder()
            .setSubject(String.valueOf(memberId)) // JWT payload의 subject에 사용자 ID 저장
            .claim("nickname", nickname) // 사용자 닉네임
            .claim("role", role) // 사용자 역할
            .setIssuedAt(now) // 발급 시간
            .setExpiration(expiryDate) // 만료 시간
            .signWith(key, SignatureAlgorithm.HS256) // 서명 알고리즘과 키 설정
            .compact(); // JWT 문자열로 직렬화
    }

    /**
     * JWT를 파싱하여 해당 토큰의 subject(memberId)를 추출
     *
     * @param token 클라이언트로 전달받은 JWT
     * @return memberId (String 타입)
     */
    public String getMemberIdFromToken(String token) {
        Claims claims = parseClaims(token);
        return claims.getSubject(); // memberId 반환
    }



    /**
     * 내부적으로 JWT에서 Claims(페이로드)만 추출
     *
     * @param token JWT 문자열
     * @return Claims 객체
     */
    private Claims parseClaims(String token) {
        try {
            return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token) // JWS 형태의 JWT만 허용 (서명 검증)
                .getBody();
        } catch (ExpiredJwtException e) {
            // 토큰이 만료됐더라도 Claims는 꺼낼 수 있으므로 따로 처리
            return e.getClaims();
        }
    }
}
