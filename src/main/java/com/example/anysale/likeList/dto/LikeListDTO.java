package com.example.anysale.likeList.dto;

import com.example.anysale.likeList.entity.LikeList;
import lombok.*;

import java.time.LocalDateTime;

@Getter
@Setter
@ToString
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class LikeListDTO {


  private int id;                  // 찜 목록 ID
  private String itemCode;         //상품 코드, 찜한 상품의 고유 코드
  private String memberId;         //멤버아이디, 찜한 회원의 ID
  private String title;            // 상품명
  private String location;         // 주소
  private String category;         // 카테고리
  private long price;            // 금액

  // 모든 필드를 초기화하는 생성자
  public LikeListDTO(String itemCode, String memberId) {
    this.itemCode = itemCode; //상품 코드 설정
    this.memberId = memberId; //멤버 아이디 설정
  }

  // likelist엔티티를 기반으로 하는 생성자
  public LikeListDTO(LikeList likeList) {
    this.id = likeList.getId();
    this.itemCode = likeList.getProduct().getItemCode();
    this.memberId = likeList.getMember().getId();
    this.title = likeList.getProduct().getTitle();
    this.location = likeList.getProduct().getLocation();
    this.category = likeList.getProduct().getCategory();
    this.price = likeList.getProduct().getPrice();
  }

  @Override
  public String toString() {
    return "LikeListDTO{" +
        "id=" + id +
        ", itemCode='" + itemCode + '\'' +
        ", title='" + title + '\'' +
        ", location='" + location + '\'' +
        ", category='" + category + '\'' +
        ", price=" + price +
        ", memberId='" + memberId + '\'' +
        '}';
  }
}