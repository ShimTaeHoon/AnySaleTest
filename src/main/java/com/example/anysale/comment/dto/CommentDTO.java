package com.example.anysale.comment.dto;

import lombok.*;

import java.time.LocalDateTime;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
@ToString
public class CommentDTO {

    private int commentId;
    private LocalDateTime createDate;
    private LocalDateTime updateDate;
    private String content;
    private String itemCode;
    private String userId;
}
