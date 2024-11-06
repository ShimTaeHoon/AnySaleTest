package com.example.anysale.member.service;

import com.example.anysale.member.dto.MemberDTO;
import com.example.anysale.member.entity.Member;

import java.util.List;
import java.util.Optional;

public interface MemberService {

    // 회원가입 (MemberDTO를 받아서 처리)
    Member registerMember(Member memberDTO);

    // 회원 정보 수정
    void modifyMember(MemberDTO memberDTO);

    // 회원 삭제
    void deleteMember(String id);

    // 회원 단일 검색
    Optional<Member> getMemberById(String id);

    // 회원 정보 반환(마이페이지)
    MemberDTO memberInfo(String id);

    // 회원 목록 가져오기
    List<MemberDTO> getList();

    // 아이디 찾기
    Optional<String> searchById(String name, String email);

    // 비밀번호 찾기
    Optional<String> searchByPw(String id, String name, String email);

    // 아이디 중복 체크
    boolean existById(String id);

    // 이메일 중복 체크
    boolean existByEmail(String email);

    // DTO에서 엔티티로 변환
    default Member dtoToEntity(MemberDTO memberDTO) {
        return Member.builder()
                .id(memberDTO.getId())
                .password(memberDTO.getPassword())
                .name(memberDTO.getName())
                .email(memberDTO.getEmail())
                .phone(memberDTO.getPhone())
                .profilePhotoUrl(memberDTO.getProfilePhotoUrl())
                .role(memberDTO.getRole())
                .score(memberDTO.getScore())
                .build();
    }

    // 엔티티에서 DTO로 변환
    default MemberDTO entityToDto(Member entity) {
        return MemberDTO.builder()
                .id(entity.getId())
                .password(entity.getPassword())
                .name(entity.getName())
                .email(entity.getEmail())
                .phone(entity.getPhone())
                .role(entity.getRole())
                .profilePhotoUrl(entity.getProfilePhotoUrl())
                .score(entity.getScore())
                .build();
    }
}
