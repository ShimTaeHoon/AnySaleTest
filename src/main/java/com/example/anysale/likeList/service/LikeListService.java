package com.example.anysale.likeList.service;

import com.example.anysale.likeList.dto.LikeListDTO;
import com.example.anysale.likeList.entity.LikeList;
import com.example.anysale.member.entity.Member;
import com.example.anysale.product.entity.Product;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

public interface LikeListService {

  // 찜 목록에 상품 추가
  LikeList addLikeList(LikeList likeList);

  // 회원의 찜 목록 조회
  List<LikeListDTO> getLikeList(String memberId);

  // 찜 목록에서 특정 상품 제거
  LikeList removeLikeList(int likeListId);

  // 찜 목록에서 모든 상품 제거
  @Transactional
  void removeAllLikeList(String memberId);


  // DTO => Entity 변환
  default LikeList dtoToEntity(LikeListDTO dto) {
    Product product = Product.builder()
        .itemCode(dto.getItemCode())
        .build();

    Member member = Member.builder()
        .id(dto.getMemberId())
        .build();

    return LikeList.builder()
        .product(product)
        .member(member)
        .build();
  }

  // Entity => DTO 변환
  default LikeListDTO entityToDto(LikeList entity) {
    LikeListDTO dto = LikeListDTO.builder()
        .itemCode(entity.getProduct().getItemCode())
        .memberId(entity.getMember().getId())
        .build();

    return dto;
  }
}

