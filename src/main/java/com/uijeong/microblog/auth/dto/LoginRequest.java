package com.uijeong.microblog.auth.dto;

/**
 * 로그인 요청 DTO
 *
 * @param email    이메일
 * @param password 비밀번호
 */
public record LoginRequest(String email, String password) {

}
