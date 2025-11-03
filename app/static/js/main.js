document.addEventListener('DOMContentLoaded', function() {
    // 文件上传验证
    const fileInput = document.getElementById('file');
    if (fileInput) {
        fileInput.addEventListener('change', function() {
            const filePath = this.value;
            const allowedExtensions = /(\.eml|\.msg|\.txt)$/i;
            
            if (!allowedExtensions.exec(filePath)) {
                alert('Please upload a valid email file (.eml, .msg, or .txt)');
                this.value = '';
                return false;
            }
        });
    }
    
    // 自动展开第一个分析部分（在结果页面）
    const firstAccordionItem = document.querySelector('#featuresAccordion .collapse');
    if (firstAccordionItem) {
        firstAccordionItem.classList.add('show');
    }
});
