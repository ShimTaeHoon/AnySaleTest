package com.example.anysale.member.dto;

import com.example.anysale.member.entity.MemberRole;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.*;

import java.time.LocalDateTime;

@Getter
@Setter
@ToString
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class MemberDTO {

    @NotBlank(message = "아이디는 필수 입력 값입니다.")
    private String id;

    @NotBlank(message = "비밀번호는 필수 입력 값입니다.")
    @Pattern(regexp = "^(?=.*[a-zA-Z])[A-Za-z\\d@$!%*?&]{8,16}$", message = "비밀번호는 최소 8자, 최대 16자이며, 적어도 하나의 알파벳을 포함해야 합니다.")
    private String password;

    @NotBlank(message = "이름을 입력해주세요")
    private String name;

    @Pattern(regexp = "^(?:\\w+\\.?)*\\w+@(?:\\w+\\.)+\\w+$", message = "이메일 형식이 올바르지 않습니다.")
    @NotBlank(message = "이메일은 필수 입력 값입니다.")
    private String email;

    @Pattern(regexp = "^010-\\d{4}-\\d{4}$")
    @NotBlank(message = "전화번호는 필수 입력 값입니다.")
    private String phone;

    private MemberRole role;

    private double score;

    private String profilePhotoUrl;

    private LocalDateTime createDate;

    private LocalDateTime updateDate;
}

