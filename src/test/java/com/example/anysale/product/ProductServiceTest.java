//package com.example.anysale.product;
//
//import com.example.anysale.product.dto.ProductDTO;
//import com.example.anysale.product.service.ProductService;
//import org.junit.jupiter.api.Test;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.boot.test.context.SpringBootTest;
//
//import java.time.LocalDateTime;
//
//import org.junit.jupiter.api.extension.ExtendWith;
//import org.springframework.test.context.junit.jupiter.SpringExtension;
//
//import java.util.Optional;
//import java.util.List;
//
//@SpringBootTest
//@ExtendWith(SpringExtension.class)
//public class ProductServiceTest {
//
//    @Autowired
//    private ProductService productService;
//
//    @Test
//    public void testSaveProduct() {
//        // given
//        ProductDTO productDTO = ProductDTO.builder()
//                .itemCode("P001")
//                .price("10000")
//                .category("Electronics")
//                .title("SmartPhone")
//                .content("Test Product")
//                .productCondition("New")
//                .imageUrl("https://example.com/image.jpg")
//                .dealDate(LocalDateTime.now())
//                .status("Available")
//                .location("Seoul")
//                .userId("user1")
//                .build();
//
//        ProductDTO productDTO2 = ProductDTO.builder()
//                .itemCode("P002")
//                .price("20000")
//                .category("Electronics")
//                .title("Tablet")
//                .content("Test Product 2")
//                .productCondition("New")
//                .imageUrl("https://example.com/image.jpg")
//                .dealDate(LocalDateTime.now())
//                .status("Available")
//                .location("Incheon")
//                .userId("user1")
//                .build();
//
//        // when
//        productService.saveProduct(productDTO);
//        productService.saveProduct(productDTO2);
//
//        // then
//        System.out.println("Product saved successfully: " + productDTO);
//    }
//
//    @Test
//    public void testGetProductById() {
//        // given
//        String itemCode = "P001";
//
//        // when
//        Optional<ProductDTO> productDTO = productService.getProductById(itemCode);
//
//        // then
//        if (productDTO.isPresent()) {
//            System.out.println("Product found: " + productDTO.get());
//        } else {
//            System.out.println("Product not found with itemCode: " + itemCode);
//        }
//    }
//
//    @Test
//    public void testGetAllProducts() {
//        // when
//        List<ProductDTO> products = productService.getAllProducts();
//
//        // then
//        System.out.println("All Products: ");
//        products.forEach(System.out::println);
//    }
//
//    @Test
//    public void testUpdateProduct() {
//        // given
//        String itemCode = "P001";
//        Optional<ProductDTO> productOpt = productService.getProductById(itemCode);
//
//        if (productOpt.isPresent()) {
//            ProductDTO productDTO = productOpt.get();
//            productDTO.setPrice("15000");  // 가격 수정
//            productDTO.setContent("Updated Test Product");  // 내용 수정
//
//            // when
//            ProductDTO updatedProduct = productService.updateProduct(itemCode, productDTO);
//
//            // then
//            System.out.println("Product updated: " + updatedProduct);
//        } else {
//            System.out.println("Product not found with itemCode: " + itemCode);
//        }
//    }
//
//    @Test
//    public void testDeleteProduct() {
//        // given
//        String itemCode = "P001";
//
//        // when
//        productService.deleteProduct(itemCode);
//
//        // then
//        Optional<ProductDTO> productDTO = productService.getProductById(itemCode);
//        if (productDTO.isPresent()) {
//            System.out.println("Failed to delete Product with itemCode: " + itemCode);
//        } else {
//            System.out.println("Product deleted successfully with itemCode: " + itemCode);
//        }
//    }
//}