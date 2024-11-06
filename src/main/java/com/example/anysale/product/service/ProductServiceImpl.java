package com.example.anysale.product.service;

import com.example.anysale.product.dto.ProductDTO;
import com.example.anysale.product.entity.Product;
import com.example.anysale.product.repository.ProductRepository;
import com.example.anysale.util.FileUtil;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@Transactional
public class ProductServiceImpl implements ProductService {

    private final ProductRepository productRepository;

    @Autowired
    public ProductServiceImpl(ProductRepository productRepository) {
        this.productRepository = productRepository;
    }

    @Autowired
    private FileUtil fileUtil;

    private static final String CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    private static final SecureRandom random = new SecureRandom();

    // 지정된 길이만큼 랜덤 문자열 생성
    private String generateRandomItemCode(int length) {
        StringBuilder itemCode = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            itemCode.append(CHARACTERS.charAt(random.nextInt(CHARACTERS.length())));
        }
        return itemCode.toString();
    }

    @Override
    public ProductDTO saveProduct(ProductDTO productDTO) {
        if (productDTO.getItemCode() == null || productDTO.getItemCode().isEmpty()) {
            productDTO.setItemCode(generateRandomItemCode(14));  // 14자리의 랜덤 상품 코드 생성
        }

        productDTO.setStatus("대기중");

        Product product = dtoToEntity(productDTO);

        String imageUrl = null;
        if (productDTO.getUploadFile() != null && !productDTO.getUploadFile().isEmpty()) {
            imageUrl = fileUtil.fileUpload(productDTO.getUploadFile());
        }
        product.setImageUrl(imageUrl);

        Product savedProduct = productRepository.save(product);
        return entityToDto(savedProduct);
    }

    @Override
    public Optional<ProductDTO> getProductById(String itemCode) {
        Optional<Product> product = productRepository.findById(itemCode);
        System.out.println("ProductServiceImpl의 getProductById 메서드가 받은 itemCode: " + itemCode);

        return product.map(this::entityToDto);
    }


    @Override
    public List<ProductDTO> getAllProducts() {
        List<Product> products = productRepository.findAllByOrderByCreateDateDesc();
        return products.stream()
                .map(this::entityToDto)
                .collect(Collectors.toList());
    }

    @Override
    public ProductDTO updateProduct(String itemCode, ProductDTO productDTO) {
        Optional<Product> productOpt = productRepository.findById(itemCode);
        if (productOpt.isPresent()) {
            Product product = productOpt.get();
            product.setPrice(productDTO.getPrice());
            product.setCategory(productDTO.getCategory());
            product.setTitle(productDTO.getTitle());
            product.setContent(productDTO.getContent());
            product.setProductCondition(productDTO.getProductCondition());
            product.setImageUrl(productDTO.getImageUrl());
            product.setDealDate(productDTO.getDealDate());
            product.setStatus(productDTO.getStatus());
            product.setLocation(productDTO.getLocation());
            Product updatedProduct = productRepository.save(product);
            return entityToDto(updatedProduct);
        } else {
            throw new IllegalArgumentException("Product not found with itemCode: " + itemCode);
        }
    }

    @Override
    public void deleteProduct(String itemCode) {
        productRepository.deleteById(itemCode);
    }

    @Override
    public Page<ProductDTO> getPagedProducts(int page, int size) {
        Pageable pageable = PageRequest.of(page, size, Sort.by("createDate").descending());
        Page<Product> productPage = productRepository.findAll(pageable);
        return productPage.map(this::entityToDto);
    }

    @Override
    public Page<ProductDTO> searchProducts(String searchType, String keyword, int page, int size) {
        Pageable pageable = PageRequest.of(page, size, Sort.by("createDate").descending());

        Page<Product> productsPage;
        if ("category".equalsIgnoreCase(searchType)) {
            productsPage = productRepository.findByCategoryContaining(keyword, pageable);
        } else {
            productsPage = productRepository.findByTitleContaining(keyword, pageable);
        }

        return productsPage.map(this::entityToDto);
    }

    @Override
    public Page<ProductDTO> searchProductsByTitle(String title, int page, int size) {
        Pageable pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "createDate") );
        Page<Product> productPage = productRepository.findByTitleContaining(title, pageable);
        return productPage.map(this::entityToDto);
    }

    @Override
    public Page<ProductDTO> searchProductsByCategory(String category, int page, int size) {
        Pageable pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "createDate"));
        Page<Product> productPage = productRepository.findByCategoryContaining(category, pageable);
        return productPage.map(this::entityToDto);
    }

    @Override
    public List<ProductDTO> getProductsWithValidUserId(String userId) {
        List<Product> products = productRepository.findProductsByUserId(userId);
        return products.stream()
                .map(this::entityToDto)
                .collect(Collectors.toList());
    }

}
