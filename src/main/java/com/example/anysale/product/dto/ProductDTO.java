package com.example.anysale.product.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.*;
import org.springframework.web.multipart.MultipartFile;

import java.time.LocalDateTime;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
@ToString
public class ProductDTO {
    private String itemCode;
    private Long price;
    private String category;
    private String title;
    private String content;
    private String productCondition;
    private LocalDateTime dealDate;
    private String status;
    private String location;
    private String userId;
    private LocalDateTime createDate;
    private LocalDateTime updateDate;

    private MultipartFile uploadFile; // 파일 스트림
    private String imageUrl;
}
