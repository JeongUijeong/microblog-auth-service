package com.uijeong.microblog.auth.service;

import com.uijeong.microblog.auth.client.MemberClient;
import com.uijeong.microblog.auth.dto.MemberResponse;
import java.util.List;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * UserDetailsService 구현체
 */
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final MemberClient memberClient;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // member-service 에서 사용자 정보 조회 (email 기준)
        MemberResponse member = memberClient.findByEmail(username);

        // ["USER","ADMIN"]
        List<SimpleGrantedAuthority> authorities = member.roles().stream()
            .map(role -> {
                String r = role.startsWith("ROLE_") ? role : "ROLE_" + role;
                return new SimpleGrantedAuthority(r);
            })
            .collect(Collectors.toList());

        // Spring Security 의 User 객체 사용 (사용자명, 암호(hashed), 권한들)
        return new User(member.email(), member.password(), authorities);
    }
}
