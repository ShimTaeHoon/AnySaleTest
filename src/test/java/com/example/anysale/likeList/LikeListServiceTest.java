package com.example.anysale.likeList;

import com.example.anysale.likeList.dto.LikeListDTO;
import com.example.anysale.likeList.service.LikeListService;
import com.example.anysale.member.service.MemberService;
import com.example.anysale.product.service.ProductService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;

@SpringBootTest
public class LikeListServiceTest {

  @Autowired
  LikeListService likeListService;

  @Autowired
  MemberService memberService;

  @Autowired
  ProductService productService;

  // 확인
  @Test
  public void 확인() {
    System.out.println(likeListService);
    System.out.println(memberService);
    System.out.println(productService);
  }

  // 회원, 상품, 찜 등록
  @Test
  void 찜상품조회() {
    List<LikeListDTO> list = likeListService.getLikeList("user1");
    for (LikeListDTO dto : list) {
      System.out.println(dto);
    }
  }


}
