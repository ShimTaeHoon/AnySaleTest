package com.example.anysale.member.controller;

import com.example.anysale.member.dto.MemberDTO;
import com.example.anysale.member.entity.Member;
import com.example.anysale.member.entity.MemberRole;
import com.example.anysale.member.repository.MemberRepository;
import com.example.anysale.member.service.MemberService;
import com.example.anysale.product.dto.ProductDTO;
import com.example.anysale.product.service.ProductService;
import com.example.anysale.security.dto.AuthMemberDTO;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.*;

@Controller
@RequiredArgsConstructor
@Log4j2
public class MemberController {

    private final MemberService memberService;
    private final MemberRepository memberRepository;
    private final ProductService productService;
    private final PasswordEncoder passwordEncoder;
//    private final MemberUserDetailsService2 memberUserDetailsService;

    // 임시
    @GetMapping("/member/temp")
    public String temp() {

        return "temp/content";
    }

    @GetMapping("/")
    public String index() {
        return "main";
    }

    // 마이페이지
    @GetMapping("/member/myPage")
    public String myPage(Model model) {
        // SecurityContextHolder에서 사용자 정보 가져오기
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return "redirect:/member/login"; // 로그인하지 않은 경우 로그인 페이지로 리디렉션
        }

        // 사용자 ID 가져오기
        String userId = authentication.getName(); // 인증된 사용자 ID

        // 현재 회원 정보 가져오기
        MemberDTO memberDTO = memberService.memberInfo(userId);
        if (memberDTO == null) {
            model.addAttribute("errorMessage", "회원 정보를 찾을 수 없습니다.");
            return "/member/login"; // 오류 발생 시 로그인 페이지로 리디렉션
        }

        model.addAttribute("member", memberDTO);

        // 유효한 사용자 ID에 해당하는 제품 목록 가져오기
        List<ProductDTO> products = productService.getProductsWithValidUserId(userId);
        model.addAttribute("products", products); // ProductDTO 리스트 추가

        return "/member/myPage"; // 회원 정보를 보여주는 페이지로 이동
    }



    // 회원가입
    @GetMapping("/member/register")
    public String createMemberForm(Model model) {
        model.addAttribute("memberDTO", new MemberDTO()); // 폼에 바인딩할 MemberDTO 생성
        return "/member/register";
    }

    @PostMapping("/member/register")
    public String createMember(@Valid @ModelAttribute MemberDTO memberDTO, BindingResult result, Model model) {
        if (result.hasErrors()) {
            return "/member/register"; // 오류가 있으면 폼으로 돌아감
        }

        // 이메일, 아이디 중복 체크
        if (memberService.existByEmail(memberDTO.getEmail())) {
            model.addAttribute("errorMessage", memberDTO.getEmail() + "는 사용 중인 이메일입니다.");
            return "/member/register";
        }

        if (memberService.existById(memberDTO.getId())) {
            model.addAttribute("errorMessage", memberDTO.getId() + "는 사용 중인 아이디입니다.");
            return "/member/register";
        }

        // 비밀번호 인코딩은 ServiceImpl에서 처리함
        Member member = memberService.dtoToEntity(memberDTO);

        // 회원가입 처리
        memberService.registerMember(member);

        return "redirect:/"; // 로그인 후 메인 페이지로 리다이렉션
    }

    @GetMapping("/member/check-id/{id}")
    public ResponseEntity<String> checkId(@PathVariable String id) {
        if (id == null || id.isEmpty()) {
            return ResponseEntity.badRequest().body("아이디를 입력해주세요.");
        }

        boolean exists = memberService.existById(id);
        return exists ? ResponseEntity.ok("이미 사용 중인 아이디입니다.") : ResponseEntity.ok("사용 가능한 아이디입니다.");
    }

    @GetMapping("/member/check-email/{email}")
    public ResponseEntity<String> checkEmail(@PathVariable String email) {
        if (email == null || email.isEmpty()) {
            return ResponseEntity.badRequest().body("이메일을 입력해주세요.");
        }

        boolean exists = memberService.existByEmail(email);
        return exists ? ResponseEntity.ok("이미 사용 중인 이메일입니다.") : ResponseEntity.ok("사용 가능한 이메일입니다.");
    }

    // 로그인 폼 요청
    @GetMapping("/member/login")
    public String login() {
        return "/member/login";
    }

    @PostMapping("/member/login")
    public String login(@RequestParam("id") String userId,
                        @RequestParam("password") String password,
                        HttpSession session,
                        Model model) {

        Member member = memberRepository.findById(userId).orElse(null);

        if (member != null) {
            // 비밀번호 확인
            if (checkPassword(password, member.getPassword())) {
                log.info("로그인 성공: {}", member.getId());

                // 사용자 권한 설정 (하나의 역할만 사용)
                List<GrantedAuthority> authorities = Collections.singletonList(
                        new SimpleGrantedAuthority(member.getRole().name())
                );

                // Spring Security를 이용한 인증 처리
                Authentication authentication = new UsernamePasswordAuthenticationToken(
                        member.getId(), // Principal: 사용자 ID
                        null, // Credentials는 null로 설정
                        authorities // 사용자 권한
                );

                // SecurityContextHolder에 인증 정보 저장
                SecurityContextHolder.getContext().setAuthentication(authentication);

                // 세션에 사용자 ID 저장 (로그인 상태 유지)
                session.setAttribute("userId", member.getId());

                // 로그인 성공 시 사용자 권한 설정
                if (member.getRole() == MemberRole.ROLE_ADMIN) {
                    return "redirect:/member/adminPage"; // 관리자는 admin 페이지로
                }
                return "redirect:/products"; // 일반 사용자는 상품 페이지로 리다이렉션
            } else {
                log.warn("로그인 실패: 사용자 ID '{}'는 맞지만 비밀번호가 잘못되었습니다.", userId);
            }
        } else {
            log.warn("로그인 실패: 사용자 ID '{}'가 존재하지 않습니다.", userId);
        }

        // 로그인 실패 시 오류 메시지 추가
        model.addAttribute("errorMessage", "ID 또는 비밀번호가 잘못되었습니다.");
        return "/member/login"; // 로그인 페이지로 돌아감
    }

    // 비밀번호 검사
    private boolean checkPassword(String rawPassword, String encodedPassword) {
        return passwordEncoder.matches(rawPassword, encodedPassword);
    }


    // 어드민 페이지 이동
    @GetMapping("/member/adminPage")
    public String adminPage() {
        return "/member/adminPage";
    }

    // 로그아웃
    @GetMapping("/member/logout")
    public String logout(HttpSession session, RedirectAttributes redirectAttributes) {
        boolean isModified = session.getAttribute("isModified") != null; // 플래그 확인
        session.invalidate();
        if(isModified) {
            redirectAttributes.addFlashAttribute("successMessage", "회원 수정이 완료되었습니다. <br> 다시 로그인해주세요.");
            return "redirect:/member/login";
        }
        return "redirect:/products"; // 제품 페이지로 리다이렉션
    }


    // 회원 목록 페이지 (어드민만 가능)
    @GetMapping("/member/list")
    public String list(Model model) {

        List<MemberDTO> memberList = memberService.getList();
        model.addAttribute("list", memberList);
        return "member/list"; // 회원 목록 보기
    }

    // 회원 정보 수정
    @GetMapping("/member/modify")
    public String modify(@RequestParam(name = "id") String id, Model model) {
        // SecurityContextHolder에서 사용자 정보 가져오기
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        // 인증 확인
        if (authentication == null || !authentication.isAuthenticated()) {
            return "redirect:/member/login"; // 로그인하지 않은 경우 로그인 페이지로 리디렉션
        }

        String userId = authentication.getName(); // 인증된 사용자 ID (예: email 또는 username)

        // 현재 회원 정보 가져오기
        MemberDTO memberDTO = memberService.memberInfo(userId);

        // 회원 정보를 수정할 때 사용할 데이터 설정
        memberDTO.setName(memberDTO.getName());

        // 조회한 데이터를 화면에 전달
        model.addAttribute("memberDTO", memberDTO);
        model.addAttribute("userid", userId);
        return "/member/modify";
    }

    @PostMapping("/member/modify")
    public String modifyPost(@Valid @ModelAttribute("memberDTO") MemberDTO memberDTO, BindingResult result, RedirectAttributes redirectAttributes, HttpSession session) {
        System.out.println("modifyPost called"); // 로그 추가
        System.out.println("MemberDTO: " + memberDTO);

        if (result.hasErrors()) {
            result.getAllErrors().forEach(error -> {
                System.out.println("Error: " + error.getDefaultMessage());
            });
            return "/member/modify";
        }

        memberService.modifyMember(memberDTO);
        session.setAttribute("isModified", true); // 수정 완료 플래그 설정
        return "redirect:/member/logout";    // 수정 성공 시 리다이렉션
    }

    // 회원 삭제
    @PostMapping("/member/remove")
    public String remove(@RequestParam("id") String id, RedirectAttributes redirectAttributes) {
        try {
            memberService.deleteMember(id);
            redirectAttributes.addFlashAttribute("successMessage", "회원이 삭제되었습니다.");
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("errorMessage", "회원 삭제에 실패했습니다.");
        }
        return "redirect:/products";
    }

    // 아이디 찾기
    @GetMapping("/member/searchId")
    public String searchId(@RequestParam(value = "name", required = false, defaultValue = "") String name,
                           @RequestParam(value = "email", required = false, defaultValue = "") String email,
                           Model model) {
        Optional<String> memberId = memberService.searchById(name, email);

        model.addAttribute("member", new Member());

        if(memberId.isPresent()){
            model.addAttribute("successMessage", "아이디는 " +memberId.get() + "입니다.");
            return "/member/searchId";
        } else {
            model.addAttribute("errorMessage", "일치하는 회원이 없습니다.");
            return "/member/searchId";
        }
    }

    // 비밀번호 찾기
    @GetMapping("/member/searchPw")
    public String searchPw(@RequestParam(value = "id", required = false, defaultValue = "") String id,
                           @RequestParam(value = "name", required = false, defaultValue = "") String name,
                           @RequestParam(value = "email", required = false, defaultValue = "") String email, Model model) {
        Optional<String> memberId = memberService.searchById(name, email);
        Optional<String> memberPw = memberService.searchByPw(id, name, email);

        model.addAttribute("member", new Member());

        if(memberPw.isPresent() && memberId.isPresent()){
            model.addAttribute("successMessage", memberId.get() + " 님의 <br> 비밀번호는 : " + memberPw.get() + "입니다.");
            return "/member/searchPw";
        } else {
            model.addAttribute("errorMessage", "일치하는 회원이 없습니다.");
            return "/member/searchPw";
        }
    }



// ====================================================================================================================================================================================

    // 소셜 회원 관련 내용

    // 소셜 수정페이지
    @GetMapping("/member/social/socialModify")
    public String showModifyPage(Authentication authentication, Model model) {
        AuthMemberDTO authMember = (AuthMemberDTO) authentication.getPrincipal();
        model.addAttribute("member", authMember);

        Member member = memberRepository.findByEmail(authMember.getEmail(),true)
                .orElseThrow(() -> new IllegalArgumentException("회원 정보를 찾을 수 없습니다."));

        model.addAttribute("member", member);
        return "member/social/socialModify";
    }

    // 수정
    @PostMapping("/member/social/socialUpdate")
    public String updateMember(Authentication authentication, String name, String password) {
        AuthMemberDTO authMember = (AuthMemberDTO) authentication.getPrincipal();
        Member member = memberRepository.findByEmail(authMember.getEmail(), true).orElseThrow();

        // 이름 수정
        member.setName(name);

        // 비밀번호 수정
        if (password != null && !password.isEmpty()) {
            member.setPassword(passwordEncoder.encode(password));
        }

        memberRepository.save(member);
        return "redirect:/member/logout"; // 수정 완료 후 리다이렉트
    }
}
