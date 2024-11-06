//package com.example.anysale.member;
//
//import com.example.anysale.member.dto.MemberDTO;
//import com.example.anysale.member.entity.Member;
//import com.example.anysale.member.repository.MemberRepository;
//import com.example.anysale.member.service.MemberService;
//import org.junit.jupiter.api.Test;
//import org.mockito.InjectMocks;
//import org.mockito.Mock;
//import org.mockito.MockitoAnnotations;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.boot.test.context.SpringBootTest;
//
//import java.util.Optional;
//import static org.mockito.Mockito.*;
//import static org.junit.jupiter.api.Assertions.*;
//
//@SpringBootTest
//public class MemberServiceTest {
//
//    @Autowired
//    private MemberRepository memberRepository;
//
//    @Autowired
//    private MemberService memberService;
//
//    MemberDTO memberDTO;
//
//    public MemberServiceTest() {
//        MockitoAnnotations.openMocks(this);
//    }
//
//    @Test
//    public void modifyMember() {
//        MemberDTO memberDTO = memberService.memberInfo("test1");
//
//        memberDTO.setPassword("1234abcd");
//
//        memberService.modifyMember(memberDTO);
//
//    }
//
//
//    @Test
//    public void testSaveMember() {
//        Member member = Member.builder()
//                .id("testUser")
//                .password("password")
//                .name("Test User")
//                .email("test@example.com")
//                .phone("01012345678")
//                .role("ROLE_USER")
//                .score(5.0)
//                .build();
//
//        when(memberRepository.save(member)).thenReturn(member);
//
//        Member savedMember = memberService.registerMember(memberDTO,model);
//
//        assertNotNull(savedMember);
//        assertEquals("testUser", savedMember.getId());
//    }
//
//    @Test
//    public void testGetMemberById() {
//        Member member = Member.builder()
//                .id("testUser")
//                .name("Test User")
//                .email("test@example.com")
//                .phone("01012345678")
//                .role("ROLE_USER")
//                .score(5.0)
//                .build();
//
//        when(memberRepository.findById("testUser")).thenReturn(Optional.of(member));
//
//        Optional<Member> foundMember = memberService.getMemberById("testUser");
//
//        assertTrue(foundMember.isPresent());
//        assertEquals("testUser", foundMember.get().getId());
//    }
//
//    @Test
//    public void testDeleteMember() {
//        doNothing().when(memberRepository).deleteById("testUser");
//        memberService.deleteMember("testUser");
//        verify(memberRepository, times(1)).deleteById("testUser");
//    }
//}