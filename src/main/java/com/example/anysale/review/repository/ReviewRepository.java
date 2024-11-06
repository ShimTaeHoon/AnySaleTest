package com.example.anysale.review.repository;

import com.example.anysale.review.entity.Review;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ReviewRepository extends JpaRepository<Review, Integer> {

    List<Review> findBySellerId(String sellerId);

    List<Review> findByBuyerId(String buyerId);

}