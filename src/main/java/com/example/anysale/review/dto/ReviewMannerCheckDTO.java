package com.example.anysale.review.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ReviewMannerCheckDTO {

    String manner; // 매너 체크박스 항목

    int count; // 해당 매너항목 체크 개수

}
