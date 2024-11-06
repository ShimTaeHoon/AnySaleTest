package com.example.anysale.comment;

import com.example.anysale.comment.Repository.CommentRepository;
import com.example.anysale.comment.entity.Comment;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
public class CommentRepositoryTest {

    @Autowired
    CommentRepository commentRepository;

    @Test
    void createComment() {
        Comment comment = Comment.builder()
                .content("테스트 코멘트")
                .userId("testUser")
                .itemCode("item001")
                .build();

        commentRepository.save(comment);
    }

    @Test
    void findCommentById() {
        Comment comment = commentRepository.findById(1).orElse(null);
        System.out.println("Find Comment: " + comment);
    }

    @Test
    void updateComment() {
        Comment comment = commentRepository.findById(1).orElse(null);

        if (comment != null) {
            comment.setContent("수정된 테스트 코멘트");
            commentRepository.save(comment);
        } else {
            System.out.println("코멘트 ID 1번을 찾을 수 없습니다.");
        }
    }

    @Test
    void deleteComment() {
        commentRepository.deleteById(1);
    }
}
