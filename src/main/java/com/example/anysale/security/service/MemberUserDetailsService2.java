//package com.example.anysale.security.service;
//
//
//import com.example.anysale.member.entity.Member;
//import com.example.anysale.member.repository.MemberRepository;
//import com.example.anysale.security.dto.AuthMemberDTO;
//import lombok.RequiredArgsConstructor;
//import lombok.extern.log4j.Log4j2;
//import org.springframework.security.core.authority.SimpleGrantedAuthority;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.security.core.userdetails.UsernameNotFoundException;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.stereotype.Service;
//
//import java.util.Collections;
//
//@Service
//@RequiredArgsConstructor
//@Log4j2
//public class MemberUserDetailsService2 implements UserDetailsService {
//
//    private final MemberRepository memberRepository;
//    private final PasswordEncoder passwordEncoder;
//
//    @Override
//    public UserDetails loadUserByUsername(String userId) throws UsernameNotFoundException {
//        Member member = memberRepository.findById(userId)
//                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + userId));
//
//        log.info("Loaded member: {}", member);
//
//        return new AuthMemberDTO(
//                member.getId(),
//                member.getPassword(),
//                member.isFromSocial(),
//                Collections.singleton(new SimpleGrantedAuthority(member.getRole().name())) // 하나의 역할만 사용
//        );
//    }
//
//    public boolean checkPassword(String rawPassword, String encodedPassword) {
//        return passwordEncoder.matches(rawPassword, encodedPassword);
//    }
//
//    // 비밀번호 확인 메서드 추가
//    public boolean authenticate(String userId, String rawPassword) {
//        Member member = memberRepository.findById(userId)
//                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + userId));
//
//        return checkPassword(rawPassword, member.getPassword());
//    }
//}