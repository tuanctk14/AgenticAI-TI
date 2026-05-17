# Vulners API - Các Thông Tin Có Sẵn

## 📊 Thông Tin CVE Cơ Bản
- **id**: CVE ID (e.g., CVE-2021-44228)
- **title**: Tiêu đề CVE
- **description**: Mô tả chi tiết về lỗ hổng
- **type**: Loại (e.g., "cve")
- **bulletinFamily**: Loại bulletin

## 📅 Thời Gian
- **published**: Ngày công bố
- **modified**: Ngày cập nhật cuối cùng
- **timestamps**: 
  - created
  - updated
  - enriched
  - reviewed
  - webApplicabilityUpdated
  - metricsUpdated
  - contentUpdated

## 🎯 Scoring & Metrics
- **EPSS** (Exploitation Probability Scoring System):
  - epss score (0.0-1.0)
  - percentile (0-100)
  - date
- **CVSS** (Common Vulnerability Scoring System):
  - score
  - severity
  - cvss2, cvss3, cvss4 versions
- **metrics**: Các metrics từ các tổ chức khác nhau

## 🔧 Lỗ Hổng Chi Tiết
- **cwe**: CWE IDs liên quan
- **cpe**: CPE entries (phần mềm bị ảnh hưởng)
- **cpe23**: CPE 2.3 format
- **cpeConfiguration**: Cấu hình CPE
- **cpeConfigurations**: Danh sách các cấu hình CPE
- **affectedSoftware**: Phần mềm bị ảnh hưởng
- **affectedConfiguration**: Cấu hình bị ảnh hưởng

## 🛡️ Bảo Vệ & Giải Pháp
- **solutions**: Giải pháp khắc phục
- **workarounds**: Cách tạm thời
- **impacts**: Tác động
- **threatData**: Dữ liệu về mối đe dọa

## 🔗 Tham Khảo & Liên Kết
- **references**: Danh sách tham khảo
- **extraReferences**: Tham khảo bổ sung
- **href**: Liên kết tới CVE detail
- **cnaAffected**: CNA affected data
- **reporter**: Người báo cáo
- **origin**: Nguồn gốc

## 🎓 Thông Tin Bổ Sung
- **aiDescription**: Mô tả được tạo bởi AI
- **webApplicability**: Khả năng áp dụng web
- **viewCount**: Số lần xem
- **problemTypes**: Các loại vấn đề
- **assigned**: Người được gán
- **vulnStatus**: Trạng thái lỗ hổng
- **sourceAvailable**: Liệu có sẵn source code
- **lastseen**: Lần cuối cùng thấy
- **enchantments**: Cải tiến

## 🚀 Hiện Tại Đang Sử Dụng
```python
{
    "public_exploit_available": bool,
    "metasploit_available": bool,
    "exploit_count": int,
    "exploit_sources": list,
    "exploit_references": list
}
```

## 💡 Có Thể Mở Rộng Thêm
- EPSS score & percentile (có sẵn trong response)
- CVSS scores (v2, v3, v4)
- CWE IDs
- CPE entries (phần mềm bị ảnh hưởng)
- Solutions & workarounds
- Affected software details
- Web applicability
- Threat data

---

**Kết luận:** Vulners API cung cấp **rất nhiều thông tin chi tiết** về CVE, không chỉ exploit intelligence mà còn:
- Scoring data (EPSS, CVSS)
- CWE mapping
- CPE/Software affected
- Solutions
- Timestamps & history
- Threat data
- Web applicability
