//package com.example.anysale.security.service;
//
//
//import com.example.anysale.member.entity.Member;
//import com.example.anysale.member.entity.MemberRole;
//import com.example.anysale.member.repository.MemberRepository;
//
//import com.example.anysale.security.dto.AuthMemberDTO;
//import lombok.RequiredArgsConstructor;
//import lombok.extern.log4j.Log4j2;
//import org.springframework.security.core.authority.SimpleGrantedAuthority;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
//import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
//import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
//import org.springframework.security.oauth2.core.user.OAuth2User;
//import org.springframework.stereotype.Service;
//
//import java.util.Collections;
//import java.util.Optional;
//
//@Log4j2
//@Service
//@RequiredArgsConstructor
//public class MemberOAuth2UserDetailsService2 extends DefaultOAuth2UserService {
//
//    private final MemberRepository repository;
//    private final PasswordEncoder passwordEncoder;
//
//    @Override
//    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
//
//        log.info("----------------------------");
//        log.info("userRequest: " + userRequest);
//
//        String clientName = userRequest.getClientRegistration().getClientName();
//
//        log.info("clientName: " + clientName);
//        log.info(userRequest.getAdditionalParameters());
//
//        OAuth2User oAuth2User = super.loadUser(userRequest);
//
//        log.info("=======================");
//        oAuth2User.getAttributes().forEach((k, v) -> {
//            log.info("key: " + k + " value: " + v); // sub, picture, email, email_verified,... 출력
//        });
//
//        String email = null;
//        String phone = "구글소셜로그인";
//
//        if (clientName.equals("Google")) {
//            email = oAuth2User.getAttribute("email");
//        }
//
//        log.info("email: " + email);
//        log.info("phone: " + phone);
//
//        Member member = saveSocialMember(email, phone);
//
//        AuthMemberDTO authMember = new AuthMemberDTO(
//                member.getEmail(),
//                member.getPassword(),
//                true, // fromSocial
//                Collections.singleton(new SimpleGrantedAuthority(member.getRole().name())), // 하나의 역할만 사용
//                oAuth2User.getAttributes()
//        );
//        authMember.setName(member.getName());
//
//        return authMember;
//    }
//
//    private Member saveSocialMember(String email, String phone) {
//        // 기존에 동일한 이메일로 가입한 회원이 있는 경우에는 그대로 조회만
//        Optional<Member> result = repository.findByEmail(email, true);
//
//        if (result.isPresent()) {
//            Member existingMember = result.get();
//            log.info("Found member: " + existingMember);
//            return existingMember;
//        }
//
//        // 없다면 회원 추가, 패스워드는 1111, 이름은 그냥 이메일 주소로
//        Member member = Member.builder()
//                .email(email)
//                .name(email)
//                .password(passwordEncoder.encode("1111")) // 임시 비밀번호
//                .phone(phone) // 전화번호 추가
//                .fromSocial(true)
//                .role(MemberRole.ROLE_USER) // ROLE_USER 설정
//                .build();
//
//        log.info("User role: " + member.getRole());
//
//        repository.save(member);
//        return member;
//    }
//}