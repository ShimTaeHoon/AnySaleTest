package com.example.anysale.comment.service;

import com.example.anysale.comment.Repository.CommentRepository;
import com.example.anysale.comment.dto.CommentDTO;
import com.example.anysale.comment.entity.Comment;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
@Transactional
public class CommentServiceImpl implements CommentService {

    private final CommentRepository commentRepository;

    @Autowired
    public CommentServiceImpl(CommentRepository commentRepository) {
        this.commentRepository = commentRepository;
    }

    @Override
    public CommentDTO createComment(CommentDTO commentDTO) {
        Comment comment = dtoToEntity(commentDTO);
        Comment savedComment = commentRepository.save(comment);
        return entityToDto(savedComment);
    }

    @Override
    public Optional<CommentDTO> findCommentById(int id) {
        Optional<Comment> comment = commentRepository.findById(id);
        return comment.map(this::entityToDto);
    }

    @Override
    public List<CommentDTO> getAllComment() {
        List<Comment> comments = commentRepository.findAll();
        return comments.stream()
                .map(this::entityToDto)
                .toList();
    }

    @Override
    public CommentDTO updateComment(CommentDTO commentDTO) {
        Optional<Comment> commentOpt = commentRepository.findById(commentDTO.getCommentId());
        if (commentOpt.isPresent()) {
            Comment comment = commentOpt.get();
            comment.setContent(commentDTO.getContent());
            Comment updatedComment = commentRepository.save(comment);
            return entityToDto(updatedComment);
        } else {
            throw new IllegalArgumentException("CommentId not found: " + commentDTO.getCommentId());
        }
    }

    @Override
    public void deleteComment(int id) {
        commentRepository.deleteById(id);
    }

    @Override
    public List<CommentDTO> getCommentsByItemCode(String itemCode) {
        List<Comment> comments = commentRepository.findCommentByItemCode(itemCode);
        return comments.stream()
               .map(this::entityToDto)
               .toList();
    }
}
