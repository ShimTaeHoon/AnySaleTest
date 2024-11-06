package com.example.anysale.likeList.service;

import com.example.anysale.likeList.dto.LikeListDTO;
import com.example.anysale.likeList.entity.LikeList;
import com.example.anysale.likeList.repository.LikeListRepository;
import com.example.anysale.member.service.MemberService;
import com.example.anysale.product.service.ProductService;
import jakarta.persistence.EntityNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class LikeListServiceImpl implements LikeListService {

  private final LikeListRepository likeListRepository;
  private final ProductService productService;  // ProductService 추가
  private final MemberService memberService;    // MemberService 추가

  @Autowired
  public LikeListServiceImpl(LikeListRepository likeListRepository, ProductService productService, MemberService memberService) {
    this.likeListRepository = likeListRepository;
    this.productService = productService;
    this.memberService = memberService;
  }

  // 찜 목록에 상품 추가
  @Override
  public LikeList addLikeList(LikeList likeList) {
    // 상품과 회원이 유효한지 확인
    if (productService.getProductById(likeList.getProduct().getItemCode()).isEmpty()) {
      throw new EntityNotFoundException("상품을 찾을 수 없습니다.");
    }
    if (memberService.getMemberById(likeList.getMember().getId()).isEmpty()) {
      throw new EntityNotFoundException("회원 정보를 찾을 수 없습니다.");
    }
    return likeListRepository.save(likeList);
  }

  // 회원의 찜 목록 조회
  @Override
  public List<LikeListDTO> getLikeList(String memberId) {
    List<LikeList> likeLists = likeListRepository.findByMemberId(memberId);
    return likeLists.stream()
        .map(likeList -> new LikeListDTO(likeList)) // DTO 변환
        .collect(Collectors.toList());
  }

  // 찜 목록에서 특정 상품 제거
  @Override
  public LikeList removeLikeList(int likeListId) {
    LikeList likeList = likeListRepository.findById(likeListId)
        .orElseThrow(() -> new EntityNotFoundException("찜 목록이 존재하지 않습니다."));
    likeListRepository.delete(likeList);
    return likeList; // 제거된 likeList 반환 (필요한 경우)
  }

  // 찜 목록에서 모든 상품 제거
  @Override
  public void removeAllLikeList(String memberId) {
    List<LikeList> likeLists = likeListRepository.findByMemberId(memberId);
    likeLists.forEach(likeListRepository::delete);
  }
}



//@Service
//public class LikeListServiceImpl implements LikeListService {
//
//  private final LikeListRepository likeListRepository;
//
//  @Autowired
//  public LikeListServiceImpl(LikeListRepository likeListRepository) {
//    this.likeListRepository = likeListRepository;
//  }
//
//  // 찜 목록에 상품 추가
//  @Override
//  public LikeList addLikeList(LikeList likeList) {
//    return likeListRepository.save(likeList);
//  }
//
//  // 회원의 찜 목록 조회
//  @Override
//  public List<LikeListDTO> getLikeList(String memberId) {
//    List<LikeList> likeLists = likeListRepository.findByMemberId(memberId);
//    return likeLists.stream()
//        .map(likeList -> new LikeListDTO(likeList.getProduct().getItemCode(), likeList.getMember().getId())) // 수정된 부분
//        .collect(Collectors.toList());
//  }
//
//  // 찜 목록에서 특정 상품 제거
//  @Override
//  public LikeList removeLikeList(int likeListId) {
//    LikeList likeList = likeListRepository.findById(likeListId)
//        .orElseThrow(() -> new EntityNotFoundException("찜 목록이 존재하지 않습니다."));
//    likeListRepository.delete(likeList);
//    return likeList; // 제거된 likeList 반환 (필요한 경우)
//  }
//
//  // 찜 목록에서 모든 상품 제거
//  @Override
//  public void removeAllLikeList(String memberId) {
//    List<LikeList> likeLists = likeListRepository.findByMemberId(memberId);
//    likeLists.forEach(likeListRepository::delete);
//  }
//}
