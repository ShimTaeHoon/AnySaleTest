//package com.example.anysale.product;
//
//import com.example.anysale.product.entity.Product;
//import com.example.anysale.product.repository.ProductRepository;
//import org.junit.jupiter.api.Test;
//import org.junit.jupiter.api.extension.ExtendWith;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.boot.test.context.SpringBootTest;
//import org.springframework.test.context.junit.jupiter.SpringExtension;
//
//import java.security.SecureRandom;
//import java.time.LocalDateTime;
//import java.util.Optional;
//
//import java.util.List;
//import java.util.stream.IntStream;
//
//@SpringBootTest
//@ExtendWith(SpringExtension.class)
//public class ProductRepositoryTest {
//
//    @Autowired
//    private ProductRepository productRepository;
//
//    private static final String ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
//    private static final String NUMERIC = "0123456789";
//    private static final String[] CATEGORIES = {"의류", "도서", "전자제품"};
//
//    private final SecureRandom random = new SecureRandom();
//
//    // 임의의 알파벳 5글자 생성
//    private String generateRandomAlphabet() {
//        StringBuilder result = new StringBuilder(5);
//        for (int i = 0; i < 5; i++) {
//            result.append(ALPHABET.charAt(random.nextInt(ALPHABET.length())));
//        }
//        return result.toString();
//    }
//
//    // 임의의 숫자 5글자 생성
//    private String generateRandomNumber() {
//        StringBuilder result = new StringBuilder(5);
//        for (int i = 0; i < 5; i++) {
//            result.append(NUMERIC.charAt(random.nextInt(NUMERIC.length())));
//        }
//        return result.toString();
//    }
//
//    // 임의의 카테고리 선택
//    private String getRandomCategory() {
//        return CATEGORIES[random.nextInt(CATEGORIES.length)];
//    }
//
//    @Test
//    public void testSaveProduct() {
//        // given
//        Product product = Product.builder()
//                .itemCode("ITEM001")
//                .price("15000")
//                .category("Books")
//                .content("Java Programming Book")
//                .productCondition("New")
//                .imageUrl("http://example.com/book.jpg")
//                .dealDate(LocalDateTime.now())
//                .status("Available")
//                .location("Seoul")
//                .userId("user001")
//                .build();
//
//        // when
//        productRepository.save(product);
//
//        // then
//        System.out.println("Saved Product: " + product);
//    }
//
//    @Test
//    public void testFindProductById() {
//        // given
//        String itemCode = "ITEM001";
//
//        // when
//        Optional<Product> product = productRepository.findById(itemCode);
//
//        // then
//        if (product.isPresent()) {
//            System.out.println("Found Product: " + product.get());
//        } else {
//            System.out.println("Product with itemCode " + itemCode + " not found.");
//        }
//    }
//
//    @Test
//    public void testFindAllProducts() {
//        // when
//        List<Product> products = productRepository.findAll();
//
//        // then
//        System.out.println("All Products: ");
//        products.forEach(System.out::println);
//    }
//
//    @Test
//    public void testUpdateProduct() {
//        // given
//        String itemCode = "ITEM001";
//        Optional<Product> productOpt = productRepository.findById(itemCode);
//
//        // when
//        if (productOpt.isPresent()) {
//            Product product = productOpt.get();
//            product.setPrice("20000");
//            product.setContent("Updated Java Programming Book");
//
//            productRepository.save(product);
//
//            System.out.println("Updated Product: " + product);
//        } else {
//            System.out.println("Product with itemCode " + itemCode + " not found for update.");
//        }
//    }
//
//    @Test
//    public void testDeleteProduct() {
//        // given
//        String itemCode = "ITEM001";
//
//        // when
//        productRepository.deleteById(itemCode);
//
//        // then
//        Optional<Product> product = productRepository.findById(itemCode);
//        if (product.isPresent()) {
//            System.out.println("Failed to delete Product with itemCode " + itemCode);
//        } else {
//            System.out.println("Product with itemCode " + itemCode + " deleted successfully.");
//        }
//    }
//
//    @Test
//    public void addDummyProducts() {
//        IntStream.range(0, 50).forEach(i -> {
//            String itemCode = generateRandomAlphabet() + generateRandomNumber();
//            String category = getRandomCategory();
//
//            Product product = Product.builder()
//                    .itemCode(itemCode)
//                    .title("더미 상품 " + i)
//                    .price(String.valueOf(1000 + (i * 10)))  // 가격을 임의로 설정
//                    .category(category)
//                    .content("이것은 더미 상품입니다.")
//                    .productCondition("새 상품")
//                    .imageUrl("http://dummyimage.com/product" + i)
//                    .status("대기중")
//                    .location("서울")
//                    .userId("testUser")
//                    .dealDate(LocalDateTime.now().plusDays(1))
//                    .build();
//
//            productRepository.save(product);
//        });
//    }
//}
