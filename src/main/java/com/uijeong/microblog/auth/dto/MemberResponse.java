package com.uijeong.microblog.auth.dto;

/**
 * member-service에서 받아올 사용자 정보 DTO
 *
 * @param id 사용자 식별자
 * @param email 이메일
 * @param password 비밀번호
 * @param nickname 닉네임
 * @param profileImageUrl 프로필 이미지 URL
 * @param role 역할
 */
public record MemberResponse(
    Long id,
    String email,
    String password,
    String nickname,
    String profileImageUrl,
    String role
) {

}
