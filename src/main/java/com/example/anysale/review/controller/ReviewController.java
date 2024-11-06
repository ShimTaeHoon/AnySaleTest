package com.example.anysale.review.controller;

import com.example.anysale.member.dto.MemberDTO;
import com.example.anysale.member.entity.Member;
import com.example.anysale.member.service.MemberService;
import com.example.anysale.review.dto.ReviewDTO;
import com.example.anysale.review.dto.ReviewMannerCheckDTO;
import com.example.anysale.review.entity.Review;
import com.example.anysale.review.service.ReviewService;
import com.example.anysale.security.dto.AuthMemberDTO;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.stereotype.Service;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.List;
import java.util.Map;

@Controller
@RequestMapping("/review")
public class ReviewController {

    @Autowired
    ReviewService reviewService;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    MemberService memberService;

    @GetMapping("/main")
    public String main() {
        System.out.println("main call 확인: ");
        return "review/main";
    }

    @GetMapping("/register")
    public String register(Model model) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        // 인증 확인
        if (authentication == null || !authentication.isAuthenticated()) {
            return "redirect:/member/login"; // 로그인하지 않은 경우 로그인 페이지로 리디렉션
        }

        String userId = authentication.getName(); // 인증된 사용자 ID (예: email 또는 username)
        Member member = memberService.getMemberById(userId).orElse(null);

        model.addAttribute("member", member);

        return "review/register";
    }


    @PostMapping("/register")
    public String register(@ModelAttribute ReviewDTO dto, RedirectAttributes redirectAttributes) {
        System.out.println("리뷰 등록 확인: " + dto);

        int newReviewNo = reviewService.register(dto);
        redirectAttributes.addFlashAttribute("message", "리뷰가 성공적으로 등록되었습니다.");

        return "redirect:/review/list";
    }

    // 목록
    @GetMapping("/list")
    public String list(Model model) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        // 인증 확인
        if (authentication == null || !authentication.isAuthenticated()) {
            return "redirect:/member/login"; // 로그인하지 않은 경우 로그인 페이지로 리디렉션
        }

        String userId = authentication.getName(); // 인증된 사용자 ID (예: email 또는 username)
        Member member = memberService.getMemberById(userId).orElse(null);

        model.addAttribute("member", member);

        List<ReviewDTO> list = reviewService.getList();
        model.addAttribute("list", list);

        return "review/list";
    }


    // 리뷰삭제
    @PostMapping("/remove")
    public String remove(@RequestParam("no") int no, Model model) {

        reviewService.remove(no);
        return "redirect:/review/list";

    }

    // 판매자ID로 검색기능
    @GetMapping("/sellerId")
    public String ReviewSearch(@RequestParam("sellerId") String sellerId, Model model) {
        List<ReviewDTO> reviewList = reviewService.searchReviews(sellerId);

        model.addAttribute("list", reviewList);

        if (reviewList.isEmpty()) {
            model.addAttribute("message", "검색결과가 없습니다.");
        } else {
            model.addAttribute("message", sellerId + "검색 결과입니다.");
        }

        return "review/list";
    }

    // 판매자ID클릭 시 리뷰 리스트 반환
//    @GetMapping("/seller/{sellerId}")
//    public String getReviewIdList(@PathVariable String sellerId, Model model) {
//        List<ReviewDTO> sellerList = reviewService.getReviewIdList(sellerId);
//        int reviewCount = sellerList.size(); // 리뷰건수표시
//        model.addAttribute("list", sellerList);
//        model.addAttribute("reviewCount", reviewCount);
//        model.addAttribute("sellerId", sellerId);
//        return "review/seller";
//    }
    // 판매자ID클릭 시 리뷰 리스트 반환
    @GetMapping("/seller/{sellerId}")
    public String getReviewIdList(@PathVariable String sellerId, Model model) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        // 인증 확인
        if (authentication == null || !authentication.isAuthenticated()) {
            return "redirect:/member/login"; // 로그인하지 않은 경우 로그인 페이지로 리디렉션
        }

        String userId = authentication.getName(); // 인증된 사용자 ID (예: email 또는 username)
        Member member = memberService.getMemberById(userId).orElse(null);

        List<ReviewDTO> sellerList = reviewService.getReviewIdList(sellerId);
        int reviewCount = sellerList.size(); // 리뷰건수표시

        model.addAttribute("member", member);
        model.addAttribute("list", sellerList);
        model.addAttribute("reviewCount", reviewCount);
        model.addAttribute("sellerId", sellerId);
        return "review/seller";
    }

    @GetMapping("/manner/{sellerId}")
    public String mannerCheck(@PathVariable String sellerId, Model model) {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        // 인증 확인
        if (authentication == null || !authentication.isAuthenticated()) {
            return "redirect:/member/login"; // 로그인하지 않은 경우 로그인 페이지로 리디렉션
        }

        String userId = authentication.getName(); // 인증된 사용자 ID (예: email 또는 username)
        Member member = memberService.getMemberById(userId).orElse(null);

        List<ReviewDTO> sellerList = reviewService.getReviewIdList(sellerId); // 거래후기 카운트
        Map<String, Integer> mannerCounts = reviewService.getMannerCountBySellerId(sellerId); // 매너 체크 카운트
        int reviewCount = sellerList.size(); // 리뷰건수표시

        System.out.println("Manner Counts(Controller): " + mannerCounts); // 로그 확인

        model.addAttribute("member", member);
        model.addAttribute("list", sellerList);
        model.addAttribute("reviewCount", reviewCount);
        model.addAttribute("mannerCounts", mannerCounts);
        return "review/manner";

    }

    // 구매자ID 클릭시 작성한 리뷰 목록 반환
    @GetMapping("/buyer/{buyerId}")
    public String getReviewsByBuyerId(@PathVariable String buyerId, Model model) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        // 인증 확인
        if (authentication == null || !authentication.isAuthenticated()) {
            return "redirect:/member/login"; // 로그인하지 않은 경우 로그인 페이지로 리디렉션
        }

        String userId = authentication.getName(); // 인증된 사용자 ID
        Member member = memberService.getMemberById(userId).orElse(null);

        List<ReviewDTO> reviewList = reviewService.getReviewsByBuyerId(buyerId); // 구매자 ID로 리뷰 목록 조회
        int reviewCount = reviewList.size(); // 리뷰 건수 표시

        model.addAttribute("member", member);
        model.addAttribute("list", reviewList);
        model.addAttribute("reviewCount", reviewCount);
        model.addAttribute("buyerId", buyerId);

        return "review/buyer"; // 리뷰 목록을 보여줄 뷰로 이동
    }

    @GetMapping("/onsale")
    public String onSale(@RequestParam(value = "sellerId", required = false) String sellerId, Model model) {
        model.addAttribute("sellerId", sellerId);

        return "review/onsale"; // onsale.html로 이동
    }
}