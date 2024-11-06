package com.example.anysale.util;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.UUID;

@Component
public class FileUtil {

    // 이미지 파일을 저장할 경로
    @Value("${filepath}")
    String filepath;

    public String fileUpload(MultipartFile multipartFile) {
        System.out.println("파일 업로드 메서드 호출됨");
        if (multipartFile.isEmpty()) { // 파일이 없으면 메서드 종료
            return null;
        }

        try {
            // 파일 저장 경로
            Path uploadPath = Paths.get(filepath);

            // 디렉토리가 존재하지 않으면 생성
            if (!Files.exists(uploadPath)) {
                Files.createDirectories(uploadPath);
                System.out.println("디렉토리를 생성했습니다: " + uploadPath.toAbsolutePath());
            }

            // 원본 파일명과 확장자 분리
            String originalFilename = StringUtils.cleanPath(multipartFile.getOriginalFilename());
            String fileExtension = getFileExtension(originalFilename); // 확장자 추출

            // 난수화된 파일명 생성 (UUID 사용)
            String randomFilename = generateRandomFilename() + fileExtension; // 난수화된 파일명과 확장자 결합

            // 저장할 파일 전체 경로 (난수화된 파일명 사용)
            Path copyOfLocation = uploadPath.resolve(randomFilename);

            // 파일을 지정한 경로에 저장 (덮어쓰기 허용)
            Files.copy(multipartFile.getInputStream(), copyOfLocation, StandardCopyOption.REPLACE_EXISTING);

            System.out.println("파일 업로드 성공: " + copyOfLocation.getFileName());

            // 업로드된 파일 이름 반환
            return randomFilename;

        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("파일 업로드 중 오류가 발생했습니다.");
        }
    }

    // 난수화된 파일명 생성 (UUID 사용)
    private String generateRandomFilename() {
        return UUID.randomUUID().toString();
    }

    // 파일 확장자 추출
    private String getFileExtension(String filename) {
        int dotIndex = filename.lastIndexOf('.');
        return (dotIndex == -1) ? "" : filename.substring(dotIndex);
    }
}