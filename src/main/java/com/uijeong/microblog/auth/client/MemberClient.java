package com.uijeong.microblog.auth.client;

import com.uijeong.microblog.auth.config.FeignConfig;
import com.uijeong.microblog.auth.dto.MemberResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * member-service의 사용자 조회 API 호출용 Feign Client
 */
@FeignClient(name = "member-service", configuration = FeignConfig.class)
public interface MemberClient {

    // 내부 호출
    @GetMapping("/interal/members")
    MemberResponse findByEmail(@RequestParam("email") String email);
}
