package com.example.anysale.review.entity;

import com.example.anysale.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;

import java.util.List;

@Getter
@Setter
@ToString
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name="review")
public class Review extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    int reviewNo; // 리뷰 고유no(게시글 번호)

    @Column(length = 50, nullable = false)
    String buyerId; // 회원 테이블의 FK(구매자)

    @Column(length = 50, nullable = false)
    String sellerId; // 회원 테이블의 FK(판매자)

//    @Column(length = 50, nullable = false)
//    String sellerMannerTemperature; // 판매자 매너온도
//
//    @Column(length = 255, nullable = false)
//    String sellerProfile; // 판매자 프사 url
//
//    @Column(length = 50, nullable = false)
//    String sellerReTransactionRate; // 재거래 희망률

    @Column(length = 50, nullable = false)
    String comment; // 리뷰 내용

    @Column(length = 50, nullable = false)
    String buyerAddress; // 구매자의 지역

    @Column(length = 255, nullable = false)
    String buyerProfile; // 구매자 프사 url

    @ElementCollection
    @Column(length = 255, nullable = true)
    List<String> mannerCheck;

    @Column(length = 50, nullable = false)
    int rating; // 별점

}
