package com.example.anysale.comment;

import com.example.anysale.comment.dto.CommentDTO;
import com.example.anysale.comment.service.CommentService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
public class CommentServiceTest {

    @Autowired
    private CommentService commentService;

    @Test
    public void testCreateComment() {
        CommentDTO commentDTO = CommentDTO.builder()
                .content("테스트 코멘트 내용 2")
                .userId("user1")
                .itemCode("P001")
                .build();

        commentService.createComment(commentDTO);
    }

    @Test
    public void testFindComment() {
        CommentDTO findComment = commentService.findCommentById(2).orElse(null);
        System.out.println("찾은 코멘트: " + findComment);
    }

    @Test
    public void testFindAllComments() {
        commentService.getAllComment().forEach(System.out::println);
    }
    
    @Test
    public void testUpdateComment() {
        int commentId = 2;
        CommentDTO findComment = commentService.findCommentById(commentId).orElse(null);
        
        if (findComment != null) {
            findComment.setContent("수정된 테스트 코멘트");
            commentService.updateComment(findComment);
        }
    }

    @Test
    public void testDeleteComment() {
        int commentId = 3;
        commentService.deleteComment(commentId);
    }
}
