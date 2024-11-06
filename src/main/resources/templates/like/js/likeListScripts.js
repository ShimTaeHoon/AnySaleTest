function bookmark() {
    const likeList = {
        itemCode: YO5AFY30Z92QFX,
        memberId: a
    };

    fetch('/likeList', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(likeList),
    })
        .then(response => response.json())
        .then(data => {
            if (data) {
                alert('찜 목록에 추가되었습니다.');
            } else {
                alert('찜 목록 추가에 실패했습니다.');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert('오류가 발생했습니다.');
        });
}


/*
fetch(`/likeList/list?memberId=${memberId}`)
    .then(response => {
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
        return response.json();
    })
    .then(data => {
        console.log(data);  // 데이터를 콘솔에 출력하여 확인
        const productList = document.querySelector('.product-list');
        productList.innerHTML = ''; // 기존 내용을 초기화
        data.forEach(item => {
            const productItem = document.createElement('div');
            productItem.classList.add('product-item');
            productItem.innerHTML = `
                <img src="assets/item/johwan.jpg" alt="상품 이미지">
                <div class="product-info">
                    <div class="div-temp1">
                        <h2>${item.itemCode}</h2>
                        <p>상품 설명</p>
                        <span class="product-price">가격 정보</span>
                    </div>
                    <div class="div-temp2">
                        <button class="like-button" onclick="removeLikeList('${item.itemCode}')">
                            <img src="assets/icon/heart.gif" alt="찜하기">
                        </button>
                    </div>
                </div>
            `;
            productList.appendChild(productItem);
        });
    })
    .catch(error => {
        console.error('There was a problem with the fetch operation:', error);
    });
//*/
