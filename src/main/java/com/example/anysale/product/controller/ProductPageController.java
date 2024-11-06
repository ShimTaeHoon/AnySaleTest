package com.example.anysale.product.controller;

import com.example.anysale.member.dto.MemberDTO;
import com.example.anysale.member.entity.Member;
import com.example.anysale.member.service.MemberService;
import com.example.anysale.product.dto.ProductDTO;
import com.example.anysale.product.entity.Product;
import com.example.anysale.product.service.ProductService;
import com.example.anysale.comment.dto.CommentDTO;
import com.example.anysale.comment.service.CommentService;
import com.example.anysale.util.FileUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import jakarta.servlet.http.HttpSession;

import java.security.Principal;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.stream.Collectors;

@Controller
public class ProductPageController {

    private final ProductService productService;
    private final CommentService commentService;
    private final MemberService memberService;
    private final FileUtil fileUtil;

    @Autowired
    public ProductPageController(ProductService productService, CommentService commentService,
                                 MemberService memberService, FileUtil fileUtil) {
        this.productService = productService;
        this.commentService = commentService;
        this.memberService = memberService;
        this.fileUtil = fileUtil;
    }

    private String getCurrentUserId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return (authentication != null && authentication.isAuthenticated()) ? authentication.getName() : null;
    }

    private String formatElapsedTime(LocalDateTime createDate) {
        Duration duration = Duration.between(createDate, LocalDateTime.now());
        long minutes = duration.toMinutes();
        if (minutes < 1) return "방금 전";
        if (minutes < 60) return minutes + "분 전";
        long hours = minutes / 60;
        if (hours < 24) return hours + "시간 전";
        long days = hours / 24;
        return days + "일 전";
    }

    // 상품 목록 보기 (페이징 처리)
    @GetMapping("/products")
    public String showProductList(@RequestParam(value = "searchType", defaultValue = "title") String searchType,
                                  @RequestParam(value = "keyword", required = false) String keyword,
                                  @RequestParam(value = "page", defaultValue = "0") int page,
                                  @RequestParam(value = "size", defaultValue = "20") int size,
                                  Model model) {
        String userId = getCurrentUserId();
        if (userId == null) return "redirect:/member/login";

        Member member = memberService.getMemberById(userId).orElse(null);
        Page<ProductDTO> productsPage = productService.getPagedProducts(page, size);
        model.addAttribute("member", member);
        model.addAttribute("products", productsPage.getContent());
        model.addAttribute("searchType", searchType);
        model.addAttribute("keyword", keyword);
        model.addAttribute("currentPage", page);
        model.addAttribute("totalPages", Math.max(1, productsPage.getTotalPages()));

        return "product/product-list";
    }

    // 상품 등록 페이지
    @GetMapping("/products/add")
    public String showAddProductPage(Model model, Principal principal) {
//        String userId = getCurrentUserId();
//        if (userId == null) return "redirect:/member/login";

        String userId = getCurrentUserId();

        Member member = memberService.getMemberById(userId).orElse(null);
        model.addAttribute("member", member);
        model.addAttribute("productDTO", new ProductDTO());

        return "product/product-add";
    }

    @PostMapping("/products/add")
    public String addProduct(@ModelAttribute ProductDTO productDTO, @RequestParam("uploadFile") MultipartFile multipartFile) {
        if (multipartFile != null && !multipartFile.isEmpty()) {
            productDTO.setImageUrl(fileUtil.fileUpload(multipartFile));
        }
        productService.saveProduct(productDTO);
        return "redirect:/products";
    }

    // 상품 상세 페이지
    @GetMapping("/products/detail/{itemCode}")
    public String showProductDetailPage(@PathVariable("itemCode") String itemCode, Model model) {
        String userId = getCurrentUserId();
        ProductDTO productDTO = productService.getProductById(itemCode)
                .orElseThrow(() -> new IllegalArgumentException("Product not found with itemCode: " + itemCode));

        model.addAttribute("productDTO", productDTO);
        model.addAttribute("comments", commentService.getCommentsByItemCode(itemCode));
        model.addAttribute("formattedDealDate", productDTO.getDealDate().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm")));
        model.addAttribute("formattedCreateDate", formatElapsedTime(productDTO.getCreateDate()));
        if (productDTO.getUpdateDate() != null) {
            model.addAttribute("formattedUpdateDate", productDTO.getUpdateDate().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm")));
        }

        if (userId != null) {
            model.addAttribute("userid", userId);
            model.addAttribute("member", memberService.getMemberById(userId).orElse(null));
        } else {
            model.addAttribute("userid", "");
            model.addAttribute("member", new MemberDTO());
        }
        return "product/product-detail";
    }

    // 상품 수정 페이지
    @GetMapping("/products/update/{itemCode}")
    public String showUpdateProductPage(@PathVariable("itemCode") String itemCode, Model model) {
        String userId = getCurrentUserId();
        if (userId == null) return "redirect:/member/login";

        Member member = memberService.getMemberById(userId).orElse(null);
        ProductDTO productDTO = productService.getProductById(itemCode)
                .orElseThrow(() -> new IllegalArgumentException("Product not found with itemCode: " + itemCode));

        model.addAttribute("member", member);
        model.addAttribute("productDTO", productDTO);
        model.addAttribute("formattedDealDate", productDTO.getDealDate().format(DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm")));

        return "product/product-update";
    }

    @PostMapping("/products/update/{itemCode}")
    public String updateProduct(@PathVariable("itemCode") String itemCode,
                                @ModelAttribute ProductDTO productDTO,
                                @RequestParam(value = "uploadFile", required = false) MultipartFile uploadFile,
                                @RequestParam(value = "existingImageUrl", required = false) String existingImageUrl) {
        if (uploadFile != null && !uploadFile.isEmpty()) {
            productDTO.setImageUrl(fileUtil.fileUpload(uploadFile));
        } else if (existingImageUrl != null) {
            productDTO.setImageUrl(existingImageUrl);
        }
        productService.updateProduct(itemCode, productDTO);
        return "redirect:/products/detail/" + itemCode;
    }

    // Ajax 검색 처리
    @ResponseBody
    @GetMapping("/products/searchAjax")
    public Page<ProductDTO> searchProductsAjax(@RequestParam(value = "searchType", defaultValue = "title") String searchType,
                                               @RequestParam(value = "keyword", required = false) String keyword,
                                               @RequestParam(value = "page", defaultValue = "0") int page,
                                               @RequestParam(value = "size", defaultValue = "20") int size) {
        return "title".equals(searchType)
                ? productService.searchProductsByTitle(keyword, page, size)
                : "category".equals(searchType)
                ? productService.searchProductsByCategory(keyword, page, size)
                : productService.getPagedProducts(page, size);
    }


}