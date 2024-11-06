package com.example.anysale.review.service;

import com.example.anysale.review.dto.ReviewDTO;
import com.example.anysale.review.dto.ReviewMannerCheckDTO;
import com.example.anysale.review.entity.Review;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

@Service
public interface ReviewService {

    int register(ReviewDTO dto);

    default Review dtoToEntity(ReviewDTO dto) {

        Review entity = Review.builder()
                .reviewNo(dto.getReviewNo())
                .buyerId(dto.getBuyerId())
                .sellerId(dto.getSellerId())
                .reviewNo(dto.getReviewNo())
                .comment(dto.getComment())
                .rating(dto.getRating())
                .buyerAddress(dto.getBuyerAddress())
                .buyerProfile(dto.getBuyerProfile())
                .mannerCheck(dto.getMannerCheck())
                .build();

        return entity;
    }

    default ReviewDTO entityToDto(Review entity) {

        ReviewDTO dto = ReviewDTO.builder()
                .reviewNo(entity.getReviewNo())
                .buyerId(entity.getBuyerId())
                .sellerId(entity.getSellerId())
                .reviewNo(entity.getReviewNo())
                .comment(entity.getComment())
                .reviewDate(entity.getCreateDate())
                .rating(entity.getRating())
                .buyerAddress(entity.getBuyerAddress())
                .buyerProfile(entity.getBuyerProfile())
                .mannerCheck(entity.getMannerCheck())
                .mannerCheckCount(entity.getMannerCheck().size()) // 매너 체크항목 카운트
                .build();

        return dto;
    }

    List<ReviewDTO> getList();

    void remove(int no);

    // 해당 ID의 리뷰 리스트 호출
    List<ReviewDTO> getReviewIdList(String sellerId);

    // 리뷰 검색
    List<ReviewDTO> searchReviews(String search);

    // 매너 체크 카운트 추가
    Map<String, Integer> getMannerCountBySellerId(String sellerId);

    // 구매자 리뷰 리스트 호출
    List<ReviewDTO> getReviewsByBuyerId(String buyerId);

}
