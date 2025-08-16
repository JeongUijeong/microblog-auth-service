package com.uijeong.microblog.auth.config;

import feign.Logger;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Feign Client 의 커스텀 설정 정의 클래스
 */
@Configuration
public class FeignConfig {

    /**
     * Feign 로그 레벨 설정
     *
     * @return FULL: 요청/응답에 대한 모든 내용 출력
     */
    @Bean
    public Logger.Level feignLoggerLevel() {
        return Logger.Level.FULL;
    }
}
