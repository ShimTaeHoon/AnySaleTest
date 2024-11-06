package com.example.anysale.product.entity;

import com.example.anysale.common.BaseEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "product")
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
@ToString
public class Product extends BaseEntity {

    @Id
//    @Column(name = "item_code")
    private String itemCode;

    @Column(nullable = false)
    private Long price;

    @Column(nullable = false)
    private String category;

    @Column (nullable = false)
    private String title;

    @Column(nullable = false)
    private String content;

    @Column(nullable = false)
    private String productCondition;

    @Column
    private String imageUrl;

    @Column(nullable = false)
    private LocalDateTime dealDate;

    @Column(nullable = false)
    private String status;

    @Column(nullable = false)
    private String location;

    @Column(nullable = false)
    private String userId;

}

