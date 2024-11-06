package com.example.anysale.likeList.repository;

import com.example.anysale.likeList.entity.LikeList;
import org.springframework.data.jpa.repository.*;
import java.util.List;

public interface LikeListRepository extends JpaRepository<LikeList, Integer> {

  // 회원의 찜 목록 조회
  List<LikeList> findByMemberId(String memberId);

  // 찜 목록에서 특정 상품 제거
  void deleteById(int likeListId);

  // 특정회원의 찜목록 삭제
  void deleteByMemberId(String memberId);

}