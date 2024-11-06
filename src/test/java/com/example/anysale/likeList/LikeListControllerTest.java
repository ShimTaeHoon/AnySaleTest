/*
package com.example.anysale.likeList;

import com.example.anysale.likeList.controller.LikeListController;
import com.example.anysale.likeList.dto.LikeListDTO;
import com.example.anysale.likeList.entity.LikeList;
import com.example.anysale.likeList.service.LikeListService;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import java.util.Arrays;
import java.util.List;

import static org.mockito.BDDMockito.given;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;

@WebMvcTest(controllers = LikeListController.class, excludeAutoConfiguration = {org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration.class})
public class LikeListControllerTest {

  @Autowired
  private MockMvc mvc;

  @MockBean
  private LikeListService likeListService;

  //
  // 회원의 찜 목록 조회 테스트
  @Test
  public void testGetLikeList() throws Exception {
    String memberId = "2";

    // Mock된 서비스 동작 정의
    List<LikeListDTO> likeListDTOS = Arrays.asList(
        new LikeListDTO("ITEM001", memberId),
        new LikeListDTO("ITEM002", memberId)
    );

    given(likeListService.getLikeList(memberId)).willReturn(likeListDTOS);

    // MockMvc로 GET 요청 수행 및 결과 검증
    mvc.perform(MockMvcRequestBuilders.get("/likeList/{memberId}", memberId))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[0].itemCode").value("ITEM001"))
        .andExpect(jsonPath("$[1].itemCode").value("ITEM002"));
  }

  // 찜 목록에 상품 추가 테스트
  @Test
  public void testLikeList() throws Exception {
    LikeList likeList = new LikeList();
    likeList.setId(2);

    given(likeListService.addLikeList(Mockito.any(LikeList.class))).willReturn(likeList);

    String likeListJson = "{\"itemCode\":\"ITEM001\",\"memberId\":\"user1\"}";

    // MockMvc로 POST 요청 수행 및 결과 검증
    mvc.perform(post("/likeList")
            .contentType(MediaType.APPLICATION_JSON)
            .content(likeListJson))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.id").value(2));
  }

  // 찜 목록에서 특정 상품 제거 테스트
  @Test
  public void testRemoveLikeList() throws Exception {
    int likeListId = 2;

    LikeList likeList = new LikeList();
    likeList.setId(likeListId);

    given(likeListService.removeLikeList(likeListId)).willReturn(likeList);

    // MockMvc로 DELETE 요청 수행 및 결과 검증
    mvc.perform(delete("/likeList/{likeListId}", likeListId))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.id").value(likeListId));
  }

  // 찜 목록에서 모든 상품 제거 테스트
  @Test
  public void testRemoveAllLikeList() throws Exception {
    String memberId = "user1";

    // MockMvc로 DELETE 요청 수행 및 결과 검증
    mvc.perform(delete("/likeList/all/{memberId}", memberId))
        .andExpect(status().isOk());
  }
}
//
*/
