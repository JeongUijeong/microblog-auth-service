package com.uijeong.microblog.auth.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import java.security.Key;
import java.util.Date;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
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
     *
     * @param memberId 사용자 식별자
     * @param role     사용자 역할
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
     * 토큰에서 Authentication 객체 생성
     *
     * @param token JWT 토큰
     * @return Authentication 객체
     */
    public Authentication getAuthentication(String token) {
        Claims claims = parseClaims(token);
        String memberId = claims.getSubject();
        String role = claims.get("role", String.class);

        // Security 인증 객체 생성 (실제로는 UserDetailsService와 연동하는 경우도 많음)
        UserDetails userDetails = new User(memberId, "", List.of(new SimpleGrantedAuthority(role)));
        return new UsernamePasswordAuthenticationToken(userDetails, "",
            userDetails.getAuthorities());
    }

    /**
     * 토큰 유효성 검사
     *
     * @param token 검사할 토큰
     * @return 검사 결과
     */
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                .setSigningKey(key)          // 서명 키 설정
                .build()
                .parseClaimsJws(token);      // 실제로 토큰 파싱 시도

            return true;
        } catch (SecurityException | MalformedJwtException e) {
            log.warn("JWT 포맷이 유효하지 않습니다.");
        } catch (ExpiredJwtException e) {
            log.warn("JWT 토큰이 만료되었습니다.");
        } catch (UnsupportedJwtException e) {
            log.warn("지원되지 않는 JWT 토큰 입니다.");
        } catch (IllegalArgumentException e) {
            log.warn("JWT claims(페이로드) 문자열이 비어있습니다.");
        }
        return false;
    }

    /**
     * 토큰 추출
     *
     * @param request HTTP 서블릿 요청
     * @return JWT 토큰 문자열
     */
    public String resolveToken(HttpServletRequest request) {
        String bearer = request.getHeader("Authorization");
        if (bearer != null && bearer.startsWith("Bearer ")) {
            return bearer.substring(7);
        }
        return null;
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
