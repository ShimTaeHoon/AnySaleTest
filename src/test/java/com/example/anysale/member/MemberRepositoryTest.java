//package com.example.anysale.member;
//
//import com.example.anysale.member.dto.MemberDTO;
//import com.example.anysale.member.entity.Member;
//import com.example.anysale.member.repository.MemberRepository;
//import com.example.anysale.member.service.MemberService;
//import org.junit.jupiter.api.Test;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
//import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
//import org.springframework.boot.test.context.SpringBootTest;
//import org.springframework.test.context.junit.jupiter.SpringExtension;
//import org.junit.jupiter.api.extension.ExtendWith;
//
//import java.time.LocalDateTime;
//import java.util.List;
//import java.util.Optional;
//
//import static org.junit.jupiter.api.Assertions.*;
//
//@SpringBootTest
//public class MemberRepositoryTest {
//
//    @Autowired
//    private MemberRepository memberRepository;
//
//    @Autowired
//    private MemberService memberService;
//
//    @Test
//    public void testSaveMember() {
//        // Builder 패턴을 이용하여 회원 엔티티 생성
//        Member member = Member.builder()
//                .id("testUser")
//                .password("password")
//                .name("Test Name")
//                .email("test@example.com")
//                .phone("01012345678")
//                .role("ROLE_USER")
//                .score(5.0)
//                .build();
//
//        // 회원 저장
//        Member savedMember = memberRepository.save(member);
//
//        // 저장된 회원이 제대로 반환되었는지 확인
//        assertNotNull(savedMember);
//        assertEquals("testUser", savedMember.getId());
//        assertEquals("Test Name", savedMember.getName());
//    }
//
//    @Test
//    public void testFindById() {
//        // 먼저 회원을 Builder 패턴을 이용해 저장
//        Member member = Member.builder()
//                .id("testUser2")
//                .password("password")
//                .name("Another Name")
//                .email("another@example.com")
//                .phone("01098765432")
//                .role("ROLE_USER")
//                .score(4.5)
//                .build();
//        memberRepository.save(member);
//
//        // 아이디로 회원 조회
//        Optional<Member> foundMember = memberRepository.findById("testUser2");
//
//        // 조회된 회원이 존재하는지 확인
//        assertTrue(foundMember.isPresent());
//        assertEquals("Another Name", foundMember.get().getName());
//    }
//
//    @Test
//    public void testDeleteMember() {
//        // 회원 엔티티를 Builder 패턴을 이용해 생성 및 저장
//        Member member = Member.builder()
//                .id("testUser3")
//                .password("password")
//                .name("Delete Test")
//                .email("delete@example.com")
//                .phone("01011223344")
//                .role("ROLE_USER")
//                .score(3.5)
//                .build();
//        memberRepository.save(member);
//
//        // 회원 삭제
//        memberRepository.deleteById("testUser3");
//
//        // 삭제 후 해당 회원이 존재하지 않는지 확인
//        Optional<Member> deletedMember = memberRepository.findById("testUser3");
//        assertFalse(deletedMember.isPresent());
//    }
//
//    @Test
//    public void testUpdateMember() {
//        // 회원 엔티티를 Builder 패턴으로 생성 및 저장
//        Member member = Member.builder()
//                .id("testUser4")
//                .password("password")
//                .name("Original Name")
//                .email("update@example.com")
//                .phone("01022334455")
//                .role("ROLE_USER")
//                .score(4.0)
//                .build();
//        memberRepository.save(member);
//
//        // 저장된 회원 정보 수정
//        member.setName("Updated Name");
//        memberRepository.save(member);
//
//        // 수정된 회원이 제대로 업데이트되었는지 확인
//        Optional<Member> updatedMember = memberRepository.findById("testUser4");
//        assertTrue(updatedMember.isPresent());
//        assertEquals("Updated Name", updatedMember.get().getName());
//    }
//
//    @Test
//    public void 아이디찾기() {
//        Optional<String> opt = memberService.searchById("정성민", "sungmin990923@naver.co2m");
//        if(opt.isPresent()){
//            System.out.println(opt);
//        } else {
//            System.out.println("없는값입니다.");
//        }
//    }
//
//}
//
