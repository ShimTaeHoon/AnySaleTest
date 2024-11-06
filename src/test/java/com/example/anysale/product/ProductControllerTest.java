//package com.example.anysale.product;
//
//import com.example.anysale.product.controller.ProductController;
//import com.example.anysale.product.dto.ProductDTO;
//import com.example.anysale.product.service.ProductService;
//import org.junit.jupiter.api.Test;
//import org.junit.jupiter.api.extension.ExtendWith;
//import org.mockito.Mockito;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
//import org.springframework.boot.test.mock.mockito.MockBean;
//import org.springframework.http.MediaType;
//import org.springframework.test.context.junit.jupiter.SpringExtension;
//import org.springframework.test.web.servlet.MockMvc;
//
//import java.time.LocalDateTime;
//import java.util.Arrays;
//import java.util.Optional;
//
//import static org.mockito.ArgumentMatchers.any;
//import static org.mockito.ArgumentMatchers.eq;
//import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
//import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
//
//import com.fasterxml.jackson.databind.ObjectMapper;
//
//@ExtendWith(SpringExtension.class)
//@WebMvcTest(ProductController.class)
//public class ProductControllerTest {
//
//    @Autowired
//    private MockMvc mockMvc;
//
//    @MockBean
//    private ProductService productService;
//
//    @Autowired
//    private ObjectMapper objectMapper;
//
//    @Test
//    public void testGetAllProducts() throws Exception {
//        // given
//        ProductDTO product1 = ProductDTO.builder()
//                .itemCode("P001")
//                .price("10000")
//                .category("Electronics")
//                .content("Test Product 1")
//                .productCondition("New")
//                .imageUrl("https://example.com/image1.jpg")
//                .dealDate(LocalDateTime.now())
//                .status("Available")
//                .location("Seoul")
//                .userId("user1")
//                .build();
//
//        ProductDTO product2 = ProductDTO.builder()
//                .itemCode("P002")
//                .price("20000")
//                .category("Books")
//                .content("Test Product 2")
//                .productCondition("Used")
//                .imageUrl("https://example.com/image2.jpg")
//                .dealDate(LocalDateTime.now())
//                .status("Available")
//                .location("Busan")
//                .userId("user2")
//                .build();
//
//        Mockito.when(productService.getAllProducts()).thenReturn(Arrays.asList(product1, product2));
//
//        // when & then
//        mockMvc.perform(get("/api/products"))
//                .andExpect(status().isOk())
//                .andExpect(jsonPath("$[0].itemCode").value("P001"))
//                .andExpect(jsonPath("$[1].itemCode").value("P002"));
//    }
//
//    @Test
//    public void testGetProductById() throws Exception {
//        // given
//        ProductDTO product = ProductDTO.builder()
//                .itemCode("P001")
//                .price("10000")
//                .category("Electronics")
//                .content("Test Product")
//                .productCondition("New")
//                .imageUrl("https://example.com/image.jpg")
//                .dealDate(LocalDateTime.now())
//                .status("Available")
//                .location("Seoul")
//                .userId("user1")
//                .build();
//
//        Mockito.when(productService.getProductById("P001")).thenReturn(Optional.of(product));
//
//        // when & then
//        mockMvc.perform(get("/api/products/P001"))
//                .andExpect(status().isOk())
//                .andExpect(jsonPath("$.itemCode").value("P001"));
//    }
//
//    @Test
//    public void testSaveProduct() throws Exception {
//        // given
//        ProductDTO productDTO = ProductDTO.builder()
//                .itemCode("P003")
//                .price("10000")
//                .category("Electronics")
//                .content("Test Product 3")
//                .productCondition("New")
//                .imageUrl("http://via.placeholder.com/640x480")
//                .dealDate(LocalDateTime.now())
//                .status("Available")
//                .location("Seoul")
//                .userId("user1")
//                .build();
//
//        Mockito.when(productService.saveProduct(any(ProductDTO.class))).thenReturn(productDTO);
//
//        // when & then
//        mockMvc.perform(post("/api/products")
//                        .contentType(MediaType.APPLICATION_JSON)
//                        .content(objectMapper.writeValueAsString(productDTO)))
//                .andExpect(status().isOk())
//                .andExpect(jsonPath("$.itemCode").value("P003"));
//    }
//
//    @Test
//    public void testUpdateProduct() throws Exception {
//        // given
//        ProductDTO updatedProductDTO = ProductDTO.builder()
//                .itemCode("P001")
//                .price("15000")
//                .category("Electronics")
//                .content("Updated Product")
//                .productCondition("New")
//                .imageUrl("https://example.com/image.jpg")
//                .dealDate(LocalDateTime.now())
//                .status("Available")
//                .location("Seoul")
//                .userId("user1")
//                .build();
//
//        Mockito.when(productService.updateProduct(eq("P001"), any(ProductDTO.class)))
//                .thenReturn(updatedProductDTO);
//
//        // when & then
//        mockMvc.perform(put("/api/products/P001")
//                        .contentType(MediaType.APPLICATION_JSON)
//                        .content(objectMapper.writeValueAsString(updatedProductDTO)))
//                .andExpect(status().isOk())
//                .andExpect(jsonPath("$.price").value("15000"))
//                .andExpect(jsonPath("$.content").value("Updated Product"));
//    }
//
//    @Test
//    public void testDeleteProduct() throws Exception {
//        // when & then
//        mockMvc.perform(delete("/api/products/P001"))
//                .andExpect(status().isNoContent());
//
//        Mockito.verify(productService).deleteProduct("P001");
//    }
//}
