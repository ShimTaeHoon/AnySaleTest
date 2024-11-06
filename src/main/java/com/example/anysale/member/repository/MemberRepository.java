package com.example.anysale.member.repository;

import com.example.anysale.member.dto.MemberDTO;
import com.example.anysale.member.entity.Member;
import com.example.anysale.product.entity.Product;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface MemberRepository extends JpaRepository<Member, String> {

    // 계정 삭제
    @Modifying
    @Query("DELETE FROM Member m WHERE m.id = :id")
    void deleteById(@Param("id") String id);

    // 마이페이지 불러오기
    @Query("select m from Member m where m.id = :id")
    Optional<Member> selectById(@Param("id") String id);

    // 아이디 찾기
    @Query("select m.id from Member m where m.name = :name and m.email = :email")
    Optional<String> searchById(@Param("name") String name, @Param("email") String email);

    // 비밀번호 찾기 
    @Query("select m.password from Member m where m.id = :id and m.name = :name and m.email = :email")
    Optional<String> searchByPw( @Param("id") String id,@Param("name") String name, @Param("email") String email);

    // 이메일 중복 체크
    boolean existsByEmail(String email);

    // 아이디 중복 체크
    boolean existsById(String id);

    //
    @EntityGraph(attributePaths = {"roleSet"}, type = EntityGraph.EntityGraphType.LOAD)
    @Query("select m from Member m where m.fromSocial = :social and m.id =:id")
    Optional<Member> findByEmail(String id, boolean social);

    @EntityGraph(attributePaths = {"roleSet"}, type = EntityGraph.EntityGraphType.LOAD)
    @Query("select m from Member m where m.fromSocial = :social and m.email =:email")
    Optional<Member> findByEmail(String email);



}
