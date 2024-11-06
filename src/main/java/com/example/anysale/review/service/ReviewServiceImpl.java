package com.example.anysale.review.service;

import com.example.anysale.review.dto.ReviewDTO;
import com.example.anysale.review.dto.ReviewMannerCheckDTO;
import com.example.anysale.review.entity.Review;
import com.example.anysale.review.repository.ReviewRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;

@Service
public class ReviewServiceImpl implements ReviewService {

    @Autowired
    ReviewRepository reviewRepository;

//    @Override
//    public int register(ReviewDTO dto) {
//
//        System.out.println(dto);
//
//        Review entity = dtoToEntity(dto);
//        reviewRepository.save(entity);
//        int newNo = entity.getReviewNo();
//
//        System.out.println(entity);
//        return newNo;
//
//    }

    @Override
    public int register(ReviewDTO dto) {
        // 현재 인증된 사용자 정보를 가져옵니다.
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        // 인증된 사용자가 있다면, buyerId를 설정합니다.
        if (authentication != null && authentication.isAuthenticated()) {
            dto.setBuyerId(authentication.getName()); // 현재 사용자 ID 설정
        }

        // DTO를 엔티티로 변환합니다.
        Review entity = dtoToEntity(dto);
        reviewRepository.save(entity);

        // 새로운 리뷰 번호를 가져옵니다.
        int newReviewNo = entity.getReviewNo();

        // 새로운 리뷰 번호를 반환합니다.
        return newReviewNo;
    }

    @Override
    public List<ReviewDTO> getList() {
        List<Review> reviews = reviewRepository.findAll();
        List<ReviewDTO> list = new ArrayList<>();
        list = reviews.stream()
                .map(entity -> entityToDto(entity))
                .collect(Collectors.toList());

        return list;
    }

    @Override
    public void remove(int no) {

        Optional<Review> findNo = reviewRepository.findById(no);
        if (findNo.isPresent()) {
            reviewRepository.deleteById(no);
        }

    }

    @Override
    public List<ReviewDTO> getReviewIdList(String sellerId) {
        List<Review> list = reviewRepository.findBySellerId(sellerId);
        List<ReviewDTO> listDto = new ArrayList<>();

        for (Review review : list) {
            ReviewDTO dto = entityToDto(review);

            // manner Count 설정
            Map<String, Integer> mannerCounts = getMannerCountBySellerId(sellerId);
            dto.setMannerCounts(mannerCounts);
            //

            listDto.add(dto);

        }
        return listDto;
    }



    @Override
    public List<ReviewDTO> searchReviews(String sellerId) {
        List<Review> list = reviewRepository.findBySellerId(sellerId);
        List<ReviewDTO> listDto = new ArrayList<>();

        for (Review review : list) {
            ReviewDTO dto = entityToDto(review);
            listDto.add(dto);
        }

        return listDto;

    }


    //매너 체크 항목(id별)
    @Override
    public Map<String, Integer> getMannerCountBySellerId(String sellerId) {
        List<Review> reviews = reviewRepository.findBySellerId(sellerId);
        Map<String, Integer> mannerCountMap = new HashMap<>();

        for (Review review : reviews) {
            System.out.println("Review(serviceImpl): " + review);
            for (String manner : review.getMannerCheck()) {
                mannerCountMap.put(manner, mannerCountMap.getOrDefault(manner, 0) + 1);
            }
        }

        return mannerCountMap;
    }

    // 구매자ID 클릭시 구매자 리뷰 리스트 반환
    @Override
    public List<ReviewDTO> getReviewsByBuyerId(String buyerId) {

        List<Review> list = reviewRepository.findByBuyerId(buyerId);
        List<ReviewDTO> listDto = new ArrayList<>();

        for (Review review : list) {
            ReviewDTO dto = entityToDto(review);

            // sellerId를 통해 매너 카운트를 설정
            Map<String, Integer> mannerCounts = getMannerCountBySellerId(review.getSellerId());
            dto.setMannerCounts(mannerCounts);

            listDto.add(dto);
        }
        return listDto;
    }

}
