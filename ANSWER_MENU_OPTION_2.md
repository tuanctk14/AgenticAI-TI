# Câu hỏi: Menu Option 2 lấy CVE hay IOC/Malware?

## ✅ Câu trả lời: Menu Option 2 lấy **IOC, Malware, APT** - KHÔNG phải CVE

---

## Giải thích

### **Menu Option 1: "Quet CVE"**
- 📊 Lấy **CVE** từ NVD (National Vulnerability Database)
- 🎯 **Tự động so khớp** CVE với thiết bị của bạn trong CMDB
- 💾 Kết quả: Thiết bị nào bị lỗ hổng, lỗi hổng nào
- Ví dụ: Menu 1 → "log4j" → Kết quả: 10 CVEs + 2 thiết bị bị ảnh hưởng

### **Menu Option 2: "Lay Threat Intelligence"**
- 🔍 Lấy **IOC, Malware, APT, Threat Actors** từ OpenCTI
- ❌ **KHÔNG tự động so khớp** với thiết bị của bạn
- 💾 Kết quả: Quy tắc phát hiện malware, file hash, chi tiết threat actor
- Ví dụ: Menu 2 → "ransomware" → Kết quả: 4 malware indicators + YARA rules

---

## Bảng So Sánh

| Tính năng | Menu 1 (CVE) | Menu 2 (IOC/Malware) |
|-----------|---|---|
| **Lấy từ đâu** | NVD API | OpenCTI API |
| **Dữ liệu lấy về** | CVE vulnerabilities | IOC, Malware, APT, Threat actors |
| **So khớp thiết bị** | ✅ Có - tự động mapping | ❌ Không - chỉ threat intel |
| **Kết quả chính** | Thiết bị bị ảnh hưởng | Quy tắc phát hiện, file hash |
| **Dùng để** | Lập kế hoạch patch | Deploy detection rules |

---

## Ví dụ Thực Tế

### Menu 1 (CVE) - Kết quả:
```
Input: Menu 1 → "log4j"

Output:
  📋 CVE DETAILS (10 CVEs):
     1. CVE-2021-4104 (CVSS: 7.5)
     2. CVE-2022-23302 (CVSS: 8.8)
     ... etc

  💻 DEVICE IMPACT (Thiết bị bị ảnh hưởng):
     • SRV-002 (db-server-01): 10 CVEs
       - CVE-2021-4104: HIGH
       - CVE-2022-23302: HIGH
       ... etc
     
     • SRV-001 (web-server-01): 5 CVEs
       - CVE-2022-23307: HIGH
       ... etc
```

### Menu 2 (IOC) - Kết quả:
```
Input: Menu 2 → "ransomware"

Output:
  🔍 IOC/MALWARE DETAILS (4 Indicators):
     1. ransomware_mallox
        Score: 78/100, Confidence: 100%
        Pattern: rule ransomware_mallox { ... YARA rule ... }
        
     2. CactusRansomware
        Score: 50/100, Confidence: 100%
        Pattern: /* detection rule ... */
        
     ... etc

  [Không có phần "Device Impact" vì không so khớp thiết bị]
```

---

## Tại sao Menu 2 không so khớp thiết bị?

✅ **CVE so khớp thiết bị vì:**
- CVE là lỗ hổng cụ thể trong phần mềm
- Nếu thiết bị của bạn cài phần mềm đó, nó bị lỗi
- Cần biết "thiết bị nào cần patch"

❌ **IOC/Malware KHÔNG so khớp thiết bị vì:**
- IOC là dấu hiệu chung (file hash, domain, IP)
- Có thể được dùng trên bất kỳ thiết bị nào
- Thường dùng để deploy rule vào SIEM/Firewall, không phải để patch

---

## Cách Dùng Đúng

### **Tìm CVE:**
```
Menu 1 → "log4j"
↓
Kết quả: Thiết bị nào bị ảnh hưởng
↓
Quyết định: Cần patch device nào trước
```

### **Tìm IOC/Malware:**
```
Menu 2 → "ransomware"
↓
Kết quả: Quy tắc phát hiện malware, file hash
↓
Quyết định: Deploy detection rule vào SIEM
```

### **Tìm APT/Threat Actor:**
```
Menu 2 → "APT41"
↓
Kết quả: APT41 indicators, malware families, threat profiles
↓
Quyết định: Tăng cường monitoring, update detection rules
```

---

## Tóm Tắt

| Câu hỏi | Dùng Menu | Lý do |
|--------|---|---|
| "Log4j có ảnh hưởng thiết bị nào?" | Menu 1 | Cần device mapping |
| "Có malware ransomware nào?" | Menu 2 | Cần threat intel & detection rules |
| "Thiết bị nào bị lỗ hổng?" | Menu 1 | Cần device-CVE mapping |
| "APT41 dùng malware gì?" | Menu 2 | Cần threat actor intel |
| "Dữ liệu phức tạp, ko biết hỏi sao" | Menu 6 | Auto-routing sẽ chọn đúng agent |

---

## Kết Luận

**Menu Option 2 lấy IOC/Malware/APT** từ OpenCTI, không phải CVE.

Nếu bạn muốn:
- ✅ **CVE + Device Impact** → Dùng Menu 1
- ✅ **IOC + Malware + Detection Rules** → Dùng Menu 2
- ✅ **Khôi không chắc** → Dùng Menu 6 (system auto-route)

