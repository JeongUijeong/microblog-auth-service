package com.uijeong.microblog.auth.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import java.time.Instant;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Entity
@Getter
public class RefreshToken {

    // jti (JWT ID)를 PK로 사용
    @Id
    @Column(length = 64)
    private String id;

    private Long userId;

    // 만료 시간 (epoch millis or Instant)
    private Instant expiryDate;

    protected RefreshToken() {
    }

    public RefreshToken(String id, Long userId, Instant expiryDate) {
        this.id = id;
        this.userId = userId;
        this.expiryDate = expiryDate;
    }
}
