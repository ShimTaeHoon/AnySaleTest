package com.example.anysale.member.entity;

import com.example.anysale.common.BaseEntity;
import jakarta.persistence.*;
import jakarta.persistence.Entity;
import lombok.*;

import java.util.HashSet;
import java.util.Set;

@Table(name = "member")
@Getter
@Setter
@ToString
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Builder
public class Member extends BaseEntity {

    @Id
    @Column(name = "id", length = 50, nullable = false)
    private String id;

    @Column(name = "password", length = 255, nullable = false)
    private String password;

    @Column(name = "name", length = 20, nullable = false)
    private String name;

    @Column(name = "email", length = 100, nullable = false, unique = true)
    private String email;

    @Column(name = "phone", length = 20, nullable = false)
    private String phone;

    @Column(name = "profile_photo_url", length = 255)
    private String profilePhotoUrl;

    @Enumerated(EnumType.STRING)
    @Column(name = "role", length = 50)
    private MemberRole role; // 역할을 Enum 타입으로 직접 저장

    @Column(name = "score")
    private Double score;

    @Column(name = "fromSocial")
    private boolean fromSocial;

    // 역할 설정 메서드
    public void setRole(MemberRole role) {
        this.role = role; // Enum 자체로 저장
    }

    // 역할 반환 메서드
    public MemberRole getRole() {
        return this.role; // Enum 타입 그대로 반환
    }

    @ElementCollection(fetch = FetchType.EAGER)
    @Enumerated(EnumType.STRING)
    @Builder.Default
    private Set<MemberRole> roleSet = new HashSet<>();

    public void addMemberRole(MemberRole role) {
        roleSet.add(role);
    }
}