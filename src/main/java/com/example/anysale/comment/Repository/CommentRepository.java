package com.example.anysale.comment.Repository;

import com.example.anysale.comment.entity.Comment;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface CommentRepository extends JpaRepository<Comment, Integer> {
    List<Comment> findCommentByItemCode(String itemCode);
}
