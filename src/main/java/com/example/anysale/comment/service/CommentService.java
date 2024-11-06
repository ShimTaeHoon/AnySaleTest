package com.example.anysale.comment.service;

import com.example.anysale.comment.dto.CommentDTO;
import com.example.anysale.comment.entity.Comment;

import java.util.List;
import java.util.Optional;

public interface CommentService {

    CommentDTO createComment(CommentDTO commentDTO);

    Optional<CommentDTO> findCommentById(int id);

    List<CommentDTO> getAllComment();

    CommentDTO updateComment(CommentDTO commentDTO);

    void deleteComment(int id);

    List<CommentDTO> getCommentsByItemCode(String itemCode);

    default Comment dtoToEntity(CommentDTO commentDTO) {
        return Comment.builder()
                .commentId(commentDTO.getCommentId())
                .content(commentDTO.getContent())
                .itemCode(commentDTO.getItemCode())
                .userId(commentDTO.getUserId())
                .build();
    }

    default CommentDTO entityToDto(Comment comment) {
        return CommentDTO.builder()
                .commentId(comment.getCommentId())
                .content(comment.getContent())
                .itemCode(comment.getItemCode())
                .userId(comment.getUserId())
                .createDate(comment.getCreateDate())
                .updateDate(comment.getUpdateDate())
                .build();
    }

}
