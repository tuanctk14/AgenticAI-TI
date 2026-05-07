# Security Report - HTML Test

**Ngay tao:** 07/05/2026 21:36
**Loai bao cao:** executive_summary
**He thong:** CyberSec Multi-Agent (Ollama Local)

---

## DASHBOARD

| Metric | Value |
|--------|-------|
| Risk Score | 72/100 |
| Risk Level | **HIGH (7-9)** |
| Total CVEs | 50 |
| IOC (Indicators) | 50 |
| Malware Families | 50 |
| Attack Patterns | 49 |
| Affected Devices | 3 |
| Critical Matches | 2 |


## TOP 3 CRITICAL ACTIONS

| Priority | Device | CVE | Action | Timeline |
|----------|--------|-----|--------|----------|
| P1 | db-server-01 | CVE-2026-36766 | Patch immediately | 24-48 hours |


## DANH SACH CVE (50 CVEs)

| # | CVE ID | CVSS | Mức Độ | Ngày Công Bố |
|---|--------|------|--------|--------------|
| 1 | **CVE-2026-36956** | 8.8 | HIGH | 2026-04-30 |
| 2 | **CVE-2026-36957** | 7.5 | HIGH | 2026-04-30 |
| 3 | **CVE-2026-36958** | 7.5 | HIGH | 2026-04-30 |
| 4 | **CVE-2026-36959** | 7.5 | HIGH | 2026-04-30 |
| 5 | **CVE-2026-7500** | 5.4 | MEDIUM | 2026-04-30 |
| 6 | **CVE-2025-13890** | N/A | UNKNOWN | 2026-04-30 |
| 7 | **CVE-2025-14543** | 9.1 | CRITICAL | 2026-04-30 |
| 8 | **CVE-2025-51847** | N/A | UNKNOWN | 2026-04-30 |
| 9 | **CVE-2025-51849** | N/A | UNKNOWN | 2026-04-30 |
| 10 | **CVE-2025-51850** | N/A | UNKNOWN | 2026-04-30 |
| 11 | **CVE-2026-34994** | N/A | UNKNOWN | 2026-04-30 |
| 12 | **CVE-2026-34995** | N/A | UNKNOWN | 2026-04-30 |
| 13 | **CVE-2026-34996** | N/A | UNKNOWN | 2026-04-30 |
| 14 | **CVE-2026-34997** | N/A | UNKNOWN | 2026-04-30 |
| 15 | **CVE-2026-34998** | N/A | UNKNOWN | 2026-04-30 |
| 16 | **CVE-2026-36340** | 8.1 | HIGH | 2026-04-30 |
| 17 | **CVE-2026-36756** | 5.4 | MEDIUM | 2026-04-30 |
| 18 | **CVE-2026-36758** | 4.3 | MEDIUM | 2026-04-30 |
| 19 | **CVE-2026-36759** | 6.5 | MEDIUM | 2026-04-30 |
| 20 | **CVE-2026-36960** | 8.8 | HIGH | 2026-04-30 |
| 21 | **CVE-2026-38939** | 6.1 | MEDIUM | 2026-04-30 |
| 22 | **CVE-2026-38940** | 6.1 | MEDIUM | 2026-04-30 |
| 23 | **CVE-2026-4670** | 9.8 | CRITICAL | 2026-04-30 |
| 24 | **CVE-2026-5174** | 7.7 | HIGH | 2026-04-30 |
| 25 | **CVE-2022-50992** | 7.5 | HIGH | 2026-04-30 |
| 26 | **CVE-2022-50993** | 9.8 | CRITICAL | 2026-04-30 |
| 27 | **CVE-2025-51846** | 7.5 | HIGH | 2026-04-30 |
| 28 | **CVE-2025-71284** | 9.8 | CRITICAL | 2026-04-30 |
| 29 | **CVE-2026-36757** | 4.3 | MEDIUM | 2026-04-30 |
| 30 | **CVE-2026-36760** | 9.6 | CRITICAL | 2026-04-30 |
| 31 | **CVE-2026-36764** | 5.0 | MEDIUM | 2026-04-30 |
| 32 | **CVE-2026-36767** | 10.0 | CRITICAL | 2026-04-30 |
| 33 | **CVE-2026-33845** | 7.5 | HIGH | 2026-04-30 |
| 34 | **CVE-2026-36761** | 6.1 | MEDIUM | 2026-04-30 |
| 35 | **CVE-2026-36762** | 8.8 | HIGH | 2026-04-30 |
| 36 | **CVE-2026-36763** | 6.1 | MEDIUM | 2026-04-30 |
| 37 | **CVE-2026-36765** | 8.8 | HIGH | 2026-04-30 |
| 38 | **CVE-2026-36766** | 5.4 | MEDIUM | 2026-04-30 |
| 39 | **CVE-2026-3832** | 3.7 | LOW | 2026-04-30 |
| 40 | **CVE-2026-3833** | 6.5 | MEDIUM | 2026-04-30 |
| 41 | **CVE-2026-32148** | 5.9 | MEDIUM | 2026-04-30 |
| 42 | **CVE-2026-35514** | 6.5 | MEDIUM | 2026-04-30 |
| 43 | **CVE-2026-40595** | 7.5 | HIGH | 2026-04-30 |
| 44 | **CVE-2026-40600** | 8.1 | HIGH | 2026-04-30 |
| 45 | **CVE-2026-40601** | 7.5 | HIGH | 2026-04-30 |
| 46 | **CVE-2026-40603** | 6.5 | MEDIUM | 2026-04-30 |
| 47 | **CVE-2026-40904** | 8.1 | HIGH | 2026-04-30 |
| 48 | **CVE-2026-7461** | 7.2 | HIGH | 2026-04-30 |
| 49 | **CVE-2025-46115** | 7.5 | HIGH | 2026-04-30 |
| 50 | **CVE-2025-56568** | 7.5 | HIGH | 2026-04-30 |


### CVE Nghiêm Trọng Cần Ưu Tiên

- **CVE-2026-36956** (CVSS: 8.8, HIGH): A Cross-Site Request Forgery (CSRF) vulnerability exists in the web management interface of the Dbit N300 T1 Pro wireless router V1.0.0. The router...
- **CVE-2026-36957** (CVSS: 7.5, HIGH): Dbit N300 T1 Pro Easy Setup Wireless Wi-Fi Router V1.0.0 is vulnerable to Denial of Service via the boa web server URI handler. By initiating a...
- **CVE-2026-36958** (CVSS: 7.5, HIGH): A denial-of-service vulnerability exists in the U-SPEED N300 V1.0.0 wireless router. By sending a large number of concurrent HTTP requests to random...
- **CVE-2026-36959** (CVSS: 7.5, HIGH): U-SPEED N300 router V1.0.0 does not implement rate limiting or account lockout protections on the /api/login endpoint. This allows an attacker on the...
- **CVE-2025-14543** (CVSS: 9.1, CRITICAL): Improper Restriction of XML External Entity Reference vulnerability in Connext Professional (Core Libraries) allows Serialized Data External...
- **CVE-2026-36340** (CVSS: 8.1, HIGH): An issue in Krayin CRM v.2.1.5 and fixed in v.2.1.6 allows a remote attacker to execute arbitrary code via the compose email function...
- **CVE-2026-36960** (CVSS: 8.8, HIGH): A Cross-Site Request Forgery (CSRF) vulnerability exists in the web management interface of the U-SPEED N300 Rounter V1.0.0. The device does not...
- **CVE-2026-4670** (CVSS: 9.8, CRITICAL): Authentication bypass by primary weakness vulnerability in Progress Software MOVEit Automation allows Authentication Bypass....
- **CVE-2026-5174** (CVSS: 7.7, HIGH): Improper input validation vulnerability in Progress Software MOVEit Automation allows Privilege Escalation....
- **CVE-2022-50992** (CVSS: 7.5, HIGH): Weaver (Fanwei) E-cology 9.5 versions prior to 10.52 contain an arbitrary file read vulnerability in the XmlRpcServlet interface at the XML-RPC...
- **CVE-2022-50993** (CVSS: 9.8, CRITICAL): Weaver (Fanwei) E-office versions prior to 10.0_20221201 contain an unauthenticated arbitrary file upload vulnerability in the OfficeServer.php...
- **CVE-2025-51846** (CVSS: 7.5, HIGH): CryptPad 2025.3.1 allows unbounded WebSocket frame flood. A remote, unauthenticated attacker can significantly degrade or deny service for all users...
- **CVE-2025-71284** (CVSS: 9.8, CRITICAL): Synway SMG Gateway Management Software contains an OS command injection vulnerability in the RADIUS configuration endpoint at /en/9-2radius.php where...
- **CVE-2026-36760** (CVSS: 9.6, CRITICAL): An issue in the fileMd5 parameter in the /a/file/upload endpoint of JeeSite v5.15.1 allows authenticated attackers with file upload permissions to...
- **CVE-2026-36767** (CVSS: 10.0, CRITICAL): A path traversal vulnerability in the /content/images/add endpoint of shopizer v3.2.5 allows attackers write arbitrary files to any writeable path...
- **CVE-2026-33845** (CVSS: 7.5, HIGH): A flaw in GnuTLS DTLS handshake parsing allows malformed fragments with zero length and non-zero offset, leading to an integer underflow during...
- **CVE-2026-36762** (CVSS: 8.8, HIGH): An issue in the fileEntityId parameter in the /a/file/upload endpoint of JeeSite v5.15.1 allows authenticated attackers with file upload permissions...
- **CVE-2026-36765** (CVSS: 8.8, HIGH): An XML external entity (XXE) vulnerability in the /designer/loadReport endpoint of SpringBlade v4.8.0 allows authenticated attackers to execute...
- **CVE-2026-40595** (CVSS: 7.5, HIGH): Chartbrew is an open-source web application that can connect directly to databases and APIs and use the data to create charts. In version 4.9.0,...
- **CVE-2026-40600** (CVSS: 8.1, HIGH): Chartbrew is an open-source web application that can connect directly to databases and APIs and use the data to create charts. In version 4.9.0,...
- **CVE-2026-40601** (CVSS: 7.5, HIGH): Chartbrew is an open-source web application that can connect directly to databases and APIs and use the data to create charts. In version 4.9.0,...
- **CVE-2026-40904** (CVSS: 8.1, HIGH): Chartbrew is an open-source web application that can connect directly to databases and APIs and use the data to create charts. In version 4.9.0,...
- **CVE-2026-7461** (CVSS: 7.2, HIGH): Improper neutralization of inputs used in an OS command in the FSx Windows File Server volume mounting component in Amazon ECS Agent on Windows...
- **CVE-2025-46115** (CVSS: 7.5, HIGH): An issue in open5gs v.2.7.3 allows a remote attacker to cause a denial of service via a crafted PDU Session Modification Request...
- **CVE-2025-56568** (CVSS: 7.5, HIGH): Assertion failure vulnerability in the PCO (Protocol Configuration Options) parser in the SMF (Session Management Function) component of Open5GS...


## THREAT INTELLIGENCE (149 Kết Quả)


### Indicators of Compromise (IOC)

| # | Loại | Tên/Pattern | Score | Confidence |
|---|------|-------------|-------|------------|
| 1 | IOC | MacOS_Trojan_Adload_f6b18a0a | 75 | 100% |
| 2 | IOC | 3c2aa3687ac9f466ce909e2cb12b07a5 | 75 | 100% |
| 3 | IOC | win_pebbledash_auto | 75 | 100% |
| 4 | IOC | e9df1f28cfbc831b89a404816a0242ead5bb142c | 75 | 100% |
| 5 | IOC | e46907cfaf96d2fde8da8a0281e4e16958a968ed | 75 | 100% |
| 6 | IOC | b91b318a9fbb153409a846bf173e9d1bd0cc4dbf | 75 | 100% |
| 7 | IOC | b23a3738b6174f62e4696080f2d8a5f258799ce5 | 75 | 100% |
| 8 | IOC | 577c3a0ac66ff71d9541d983e37530500cb9f2a5 | 75 | 100% |
| 9 | IOC | 39c97ca820f31e7903ccb190fee02035ffdb37b9 | 75 | 100% |
| 10 | IOC | 2f78abc001534e28eb208a73245ce5389c40ddbe | 75 | 100% |


### Malware Families

| # | Tên Malware | Loại | Bí Danh | Mô Tả |
|---|-------------|------|--------|-------|
| 1 | DocSwap |  |  | [DocSwap](https://attack.mitre.org/software/S9005) is an And... |
| 2 | Crocodilus |  |  | [Crocodilus](https://attack.mitre.org/software/S9004) is an ... |
| 3 | DOWNIISSA |  |  | [DOWNIISSA](https://attack.mitre.org/software/S9021) is a sh... |
| 4 | DRYHOOK |  |  | [DRYHOOK](https://attack.mitre.org/software/S9013) is Python... |
| 5 | LazyWiper |  |  | [LazyWiper](https://attack.mitre.org/software/S9039) is a de... |
| 6 | BRUSHFIRE |  |  | [BRUSHFIRE](https://attack.mitre.org/software/S9011) is a pa... |
| 7 | Shai-Hulud |  |  | [Shai-Hulud](https://attack.mitre.org/software/S9008) is a s... |
| 8 | SPAWNCHIMERA |  |  | [SPAWNCHIMERA](https://attack.mitre.org/software/S9024) is a... |
| 9 | PHASEJAM |  |  | [PHASEJAM](https://attack.mitre.org/software/S9014) is a dro... |
| 10 | LAMEHUG |  | PROMPTSTEAL | [LAMEHUG](https://attack.mitre.org/software/S9035) is Python... |


### Attack Patterns (MITRE ATT&CK)

| # | Technique | Tên | Mô Tả |
|---|-----------|-----|-------|
| 1 | N/A | Block Communications | Operational technology communications occur over serial COM,... |
| 2 | N/A | Unauthorized Message | Adversaries may send unauthorized messages to ICS systems an... |
| 3 | N/A | Online Edit | Adversaries may execute an online edit of a PLC to update pa... |
| 4 | N/A | Broadcast Discovery | Adversaries may perform broadcast discovery requests to enum... |
| 5 | N/A | Modify Firmware | Firmware is low-level software embedded in hardware that ena... |
| 6 | N/A | Reporting Message | Adversaries may block or prevent a reporting message from re... |
| 7 | N/A | Download All | Adversaries may execute a full program download to a PLC to ... |
| 8 | N/A | Module Firmware | Adversaries may install malicious or vulnerable firmware ont... |
| 9 | N/A | Hardcoded Credentials | Adversaries may leverage credentials that are hardcoded in s... |
| 10 | N/A | System Firmware | System firmware on modern assets is often designed with an u... |


## THIET BI BI ANH HUONG (3 Thiết Bị)

| Thiết Bị | IP | OS | CVE | Mức Độ | Phần Mềm Lỗi |
|----------|----|----|-----|--------|-------------|
| web-server-01 | 192.168.1.10 | Windows Server 2019 10.0.17763 | CVE-2022-50993 | **CRITICAL** | PHP 7.4.3 |
| web-server-01 | 192.168.1.10 | Windows Server 2019 10.0.17763 | CVE-2025-71284 | **CRITICAL** | PHP 7.4.3 |
| app-server-01 | 192.168.1.30 | CentOS 7.9 | CVE-2026-36765 | **HIGH** | Spring Framework 5.3.18 |
| db-server-01 | 192.168.1.20 | Ubuntu 20.04 | CVE-2026-36766 | **MEDIUM** | OpenSSH 8.2p1 |
| web-server-01 | 192.168.1.10 | Windows Server 2019 10.0.17763 | CVE-2026-38939 | **MEDIUM** | PHP 7.4.3 |
| web-server-01 | 192.168.1.10 | Windows Server 2019 10.0.17763 | CVE-2026-38940 | **MEDIUM** | PHP 7.4.3 |
| app-server-01 | 192.168.1.30 | CentOS 7.9 | CVE-2026-36764 | **MEDIUM** | Spring Framework 5.3.18 |
| app-server-01 | 192.168.1.30 | CentOS 7.9 | CVE-2026-36763 | **MEDIUM** | Spring Framework 5.3.18 |


### Chi Tiết Khắc Phục Từng Thiết Bị


#### web-server-01 (192.168.1.10) - **CRITICAL**
- **OS**: Windows Server 2019 10.0.17763
- **Criticality**: HIGH

**Lý do bị ảnh hưởng:**
- **CVE-2022-50993** (CVSS: 9.8): Weaver (Fanwei) E-office versions prior to 10.0_20221201 contain an...
- **CVE-2025-71284** (CVSS: 9.8): Synway SMG Gateway Management Software contains an OS command injection...
- **CVE-2026-38939** (CVSS: 6.1): Cross Site Scripting vulnerability in andrewtch88 mvc-ecommerce v.1.0 allows a...
- **CVE-2026-38940** (CVSS: 6.1): Cross Site Scripting vulnerability in RafyMrX TOKO-ONLINE-ROTI v.1.0 allows a...

**Hướng khắc phục:**
- ⚡ **Ưu tiên CRITICAL**: Xử lý ngay trong 24 giờ
- **Cập nhật phần mềm**: Nâng cấp PHP 7.4.3 lên phiên bản mới nhất
- **Kiểm tra logs**: Tìm kiếm dấu hiệu bị khai thác (suspicious activities, error patterns)
- **Network segmentation**: Giới hạn truy cập từ bên ngoài nếu chưa có
- **Credential reset**: Reset tất cả passwords, invalidate sessions nếu cần
- **MFA enforcement**: Enable Multi-Factor Authentication nếu chưa có


#### app-server-01 (192.168.1.30) - **HIGH**
- **OS**: CentOS 7.9
- **Criticality**: HIGH

**Lý do bị ảnh hưởng:**
- **CVE-2026-36765** (CVSS: 8.8): An XML external entity (XXE) vulnerability in the /designer/loadReport endpoint...
- **CVE-2026-36764** (CVSS: 5.0): A Server-Side Request Forgery (SSRF) in the /ureport/datasource/testConnection...
- **CVE-2026-36763** (CVSS: 6.1): A stored cross-site scripting (XSS) vulnerability in the...

**Hướng khắc phục:**
- 🔴 **Ưu tiên HIGH**: Xử lý trong 72 giờ
- **Cập nhật phần mềm**: Nâng cấp Spring Framework 5.3.18 lên phiên bản mới nhất
- **Kiểm tra logs**: Tìm kiếm dấu hiệu bị khai thác (suspicious activities, error patterns)
- **Network segmentation**: Giới hạn truy cập từ bên ngoài nếu chưa có
- **Credential reset**: Reset tất cả passwords, invalidate sessions nếu cần
- **MFA enforcement**: Enable Multi-Factor Authentication nếu chưa có


#### db-server-01 (192.168.1.20) - **MEDIUM**
- **OS**: Ubuntu 20.04
- **Criticality**: CRITICAL

**Lý do bị ảnh hưởng:**
- **CVE-2026-36766** (CVSS: 5.4): Multiple authenticated cross-site scripting (XSS) vulnerabilities in the...

**Hướng khắc phục:**
- 🟡 **Ưu tiên MEDIUM**: Lên lịch xử lý trong 2 tuần
- **Cập nhật phần mềm**: Nâng cấp OpenSSH 8.2p1 lên phiên bản mới nhất
- **Kiểm tra logs**: Tìm kiếm dấu hiệu bị khai thác (suspicious activities, error patterns)
- **Network segmentation**: Giới hạn truy cập từ bên ngoài nếu chưa có
- **Credential reset**: Reset tất cả passwords, invalidate sessions nếu cần
- **MFA enforcement**: Enable Multi-Factor Authentication nếu chưa có


---
*Tạo bởi CyberSec Multi-Agent System | 07/05/2026 21:36:30*
*Model: Ollama Local | Report ID: 20260507_213630*
