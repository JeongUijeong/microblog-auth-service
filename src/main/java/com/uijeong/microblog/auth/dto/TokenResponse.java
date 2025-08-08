package com.uijeong.microblog.auth.dto;

/**
 * JWT 토큰 응답 DTO
 *
 * @param accessToken 엑세스 토큰
 * @param tokenType 토큰 유형
 */
public record TokenResponse(String accessToken, String tokenType) {

    public TokenResponse(String accessToken) {
        this(accessToken, "Bearer");
    }
}
