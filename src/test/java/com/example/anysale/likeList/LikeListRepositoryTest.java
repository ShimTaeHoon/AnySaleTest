package com.example.anysale.likeList;

import com.example.anysale.likeList.entity.LikeList;
import com.example.anysale.likeList.repository.LikeListRepository;
import com.example.anysale.member.entity.Member;
import com.example.anysale.member.entity.MemberRole;
import com.example.anysale.member.repository.MemberRepository;
import com.example.anysale.product.entity.Product;
import com.example.anysale.product.repository.ProductRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@SpringBootTest
public class LikeListRepositoryTest {

  @Autowired
  LikeListRepository likeListRepository;

  @Autowired
  MemberRepository memberRepository;

  @Autowired
  ProductRepository productRepository;

  // 회원 등록
  @Test
  void 회원등록() {

    MemberRole memberRole = MemberRole.ROLE_ADMIN;

    Member member = Member.builder()
        .id("user1")
        .password("u12341234")
        .name("John")
        .email("john11@naver.com")
        .phone("010-0000-0001")
        .profilePhotoUrl("http://example.com/photo.jpg")
        .role(memberRole)
        .score(10.0)
        .build();

    Member member2 = Member.builder()
        .id("user2")
        .password("u12341234")
        .name("Sophia")
        .email("Sophia22@naver.com")
        .phone("010-0000-0002")
        .profilePhotoUrl("http://example.com/photo.jpg")
        .role(memberRole)
        .score(20.0)
        .build();

    Member member3 = Member.builder()
        .id("user3")
        .password("u12341234")
        .name("Oliver")
        .email("Oliver33@naver.com")
        .phone("010-0000-0003")
        .profilePhotoUrl("http://example.com/photo.jpg")
        .role(memberRole)
        .score(30.0)
        .build();

    memberRepository.save(member);
    memberRepository.save(member2);
    memberRepository.save(member3);
  }


  // 상품 등록
  @Test
  void 상품등록() {
    Product product1 = Product.builder()
        .itemCode("ITEM001")
        .price(10000L)
        .category("중고거래")
        .title("프리미엄주환이")
        .content("내용")
        .productCondition("내용")
        .imageUrl("http://example.com/photo.jpg")
        .dealDate(LocalDateTime.now())
        .status("판매중")
        .location("구월동")
        .userId("user1")
        .build();

    Product product2 = Product.builder()
        .itemCode("ITEM002")
        .price(50000L)
        .category("알바")
        .title("단기알바")
        .content("내용")
        .productCondition("내용")
        .imageUrl("http://example.com/photo.jpg")
        .dealDate(LocalDateTime.now())
        .status("모집중")
        .location("만수동")
        .userId("user2")
        .build();

    Product product3 = Product.builder()
        .itemCode("ITEM003")
        .price(200000L)
        .category("부동산")
        .title("구월동 오피스텔")
        .content("내용")
        .productCondition("내용")
        .imageUrl("http://example.com/photo.jpg")
        .dealDate(LocalDateTime.now())
        .status("거래중")
        .location("구월동")
        .userId("user2")
        .build();

    Product product4 = Product.builder()
        .itemCode("ITEM004")
        .price(52000L)
        .category("중고거래")
        .title("프리미엄 주환이2")
        .content("내용")
        .productCondition("내용")
        .imageUrl("http://example.com/photo.jpg")
        .dealDate(LocalDateTime.now())
        .status("거래중")
        .location("주안")
        .userId("user1")
        .build();


    productRepository.save(product1);
    productRepository.save(product2);
    productRepository.save(product3);
    productRepository.save(product4);

  }


  // 찜상품 등록
  @Test
  void 찜상품등록() {

    Member member1 = Member.builder()
        .id("a")
        .build();

    Product product1 = Product.builder()
        .itemCode("YO5AFY30Z92QFX")
        .build();

    LikeList likeList1 = LikeList.builder()
        .member(member1)
        .product(product1)
        .build();

//    Member member2 = Member.builder()
//            .id("user2")
//                .build();
//
//    Product product2 = Product.builder()
//            .itemCode("ITEM002")
//                .build();
//
//    LikeList likeList2 = LikeList.builder()
//            .member(member1)
//                .product(product2)
//                        .build();
//
//    Member member3 = Member.builder()
//        .id("user2")
//        .build();
//
//    Product product3 = Product.builder()
//        .itemCode("ITEM001")
//        .build();
//
//    LikeList likeList3 = LikeList.builder()
//        .member(member1)
//        .product(product3)
//        .build();

//    Member member4 = Member.builder()
//            .id("user1")
//                .build();
//
//    Product product4 = Product.builder()
//            .itemCode("ITEM002")
//                .build();
//
//    LikeList likeList4 = LikeList.builder()
//            .member(member4)
//                .product(product4)
//                        .build();

    likeListRepository.save(likeList1);
//    likeListRepository.save(likeList2);
//    likeListRepository.save(likeList3);
//    likeListRepository.save(likeList4);
  }


  // 회원 조회
  @Test
  public void 회원목록조회() {
    List<Member> list = memberRepository.findAll();
    for(Member member : list) {
      System.out.println(member);
    }
  }

  @Test
  public void 회원단건조회() {
    Optional<Member> result = memberRepository.findById("user1");
    if(result.isPresent()) {
      Member member = result.get();
      System.out.println(member);
    }
  }


  // 상품 조회
  @Test
  public void 상품목록조회() {
    List<Product> list = productRepository.findAll();
    for(Product product : list) {
      System.out.println(product);
    }
  }

  @Test
  public void 상품단건조회() {
    Optional<Product> result = productRepository.findById("ITEM001");
    if(result.isPresent()) {
      Product product = result.get();
      System.out.println(product);
    }
  }


  // 찜상품 조회
  @Test
  public void 찜목록조회() {
    List<LikeList> list = likeListRepository.findAll();
    for(LikeList likeList : list) {
      System.out.println(likeList);
    }
  }

  @Test
  public void 찜상품조회() {
    Optional<LikeList> result = likeListRepository.findById(2);
    if(result.isPresent()) {
      LikeList likeList = result.get();
      System.out.println(likeList);
    }
  }


  // 회원 수정
  @Test
  public void 회원수정() {
    Optional<Member> result = memberRepository.findById("user1");
    Member member = result.get();
    member.setName("임마");
    memberRepository.save(member);
    }

  // 상품 수정
  @Test
  public void 상품수정() {
    Optional<Product> result = productRepository.findById("ITEM001");
    Product product = result.get();
    product.setPrice(1000L);
    productRepository.save(product);
  }

  // 찜상품 수정
  @Test
  public void 찜상품수정() {
    Optional<LikeList> result = likeListRepository.findById(2);
    LikeList likeList = result.get();
    likeListRepository.save(likeList);
  }

  // 회원 삭제
  @Test
  public void 회원삭제() {
    memberRepository.deleteById("user1");
  }

  // 상품 삭제
  @Test
  public void 상품삭제() {
    productRepository.deleteById("ITEM001");
  }

  // 찜상품 삭제
  @Test
  public void 찜상품삭제() {
    likeListRepository.deleteById(2);
  }
}
