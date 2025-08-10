package com.uijeong.microblog.auth.dto;

/**
 * 리프레시 토큰 요청 DTO
 *
 * @param refreshToken 리프레시 토큰
 */
public record RefreshRequest(
    String refreshToken
) {

}
