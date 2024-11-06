package com.example.anysale;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

@SpringBootApplication
@EnableJpaAuditing
public class AnySaleApplication {

    public static void main(String[] args) {
        SpringApplication.run(AnySaleApplication.class, args);
    }

}
