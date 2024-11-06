package com.example.anysale.config;

import com.example.anysale.member.repository.MemberRepository;
//import com.example.anysale.security.service.MemberUserDetailsService2;
import com.example.anysale.social.security.handler.LoginSuccessHandler;
import com.example.anysale.social.security.service.MemberUserDetailsService;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import java.io.IOException;

@Configuration
@EnableWebSecurity
@Log4j2
public class SecurityConfig {

    // 비밀번호 인코더 빈 생성
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(); // 비밀번호 암호화에 사용할 인코더
    }

    // HTTP 보안 설정
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, MemberRepository memberRepository) throws Exception {
        log.info("---------------filterChain---------------");

        // 요청에 대한 권한 설정
        http.authorizeHttpRequests(auth -> {
                    auth.requestMatchers("/uploadfile/**", "/likeList/**", "/products",
                                    "/member/register", "/member/**", "/css/**",
                                    "/js/**", "/review/**", "/assets/**", "/socialLogin").permitAll() // 모든 사용자에게 접근 허용
                            .requestMatchers("/member/adminPage").hasRole("ADMIN") // ROLE_ADMIN만 접근 가능
                            .requestMatchers("/member/socialRegister", "/sample/all", "/sample/member").permitAll()
                            .requestMatchers("/oauth2/**","/login/**","/login", "/member/login").permitAll()
                            .requestMatchers("/products/**").authenticated();

//                            .anyRequest().hasRole("USER"); // 그 외 모든 요청은 인증 필요
                })

                .formLogin(form -> form
                        .loginPage("/member/login") // 사용자 정의 로그인 페이지 설정
                                 .loginProcessingUrl("/login")
                        .defaultSuccessUrl("/products", true) // 로그인 성공 후 리다이렉트
                        .permitAll() // 모든 사용자 접근 허용
//                        .failureUrl("/member/login")
                        .usernameParameter("id")
                        .passwordParameter("password")
                        .successHandler(successHandler(memberRepository)) // 로그인 성공 시 커스텀 핸들러
                );
//                .logout(logout -> logout
//                        .logoutUrl("/member/logout") // 로그아웃 URL
//                        .logoutSuccessUrl("/member/logout") // 로그아웃 성공 시 리다이렉트
//                        .permitAll() // 모든 사용자 접근 허용
//                );
        // CSRF 보호 비활성화
        http.csrf(csrf -> csrf.disable());

//        // OAuth2 로그인 설정
//        http.oauth2Login(oauth2 -> oauth2
//                .loginPage("/member/login") // 사용자 정의 로그인 페이지 설정
//                .defaultSuccessUrl("/member/socialRegister") // OAuth2 로그인 성공 후 리다이렉션 URL
//                .failureUrl("/login?error") // 로그인 실패 시 리다이렉트 URL
////                .successHandler(successHandler(memberRepository)) // 로그인 성공 시 커스텀 핸들러
//        );

        // 자동 로그인 설정
//        http.rememberMe(rem -> {
//            rem.rememberMeParameter("remember"); // 리멤버 미 기능을 위한 파라미터 이름
//            rem.tokenValiditySeconds(60 * 60 * 24 * 7); // 쿠키 유효 기간 (7일)
//            rem.userDetailsService(memberUserDetailsService); // 자동 로그인 시 사용할 UserDetailsService
//        });

        return http.build(); // SecurityFilterChain 객체 반환
    }

    // LoginSuccessHandler 빈 생성
    @Bean
    public LoginSuccessHandler successHandler(MemberRepository memberRepository) {
        return new LoginSuccessHandler(passwordEncoder(), memberRepository); // 비밀번호 인코더와 회원 저장소를 주입
    }
}
