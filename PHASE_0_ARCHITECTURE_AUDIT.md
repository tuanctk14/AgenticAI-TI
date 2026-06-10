# PHASE 0: KIỂM TOÁN KIẾN TRÚC HỆ THỐNG

**Ngày**: 2026-06-10  
**Trạng thái**: HOÀN THÀNH  
**Người báo cáo**: Principal Cybersecurity Architect  
**Ngôn ngữ**: Tiếng Việt

---

## I. TỔNG QUAN KIỂM TOÁN

Báo cáo này cung cấp:
1. **Kiểm kê chi tiết** tất cả 35 mô-đun cốt lõi hiện tại
2. **Phân tích phụ thuộc** để xác định các hub cốt lõi
3. **Đánh giá khả năng tái sử dụng** cho Graph MCP, Threat Memory MCP, Log MCP, GraphRAG
4. **Chiến lược tích hợp** mà không làm thay đổi kiến trúc hiện tại
5. **Khuyến nghị ưu tiên** dựa trên độ phức tạp và giá trị

### Kết luận tổng thể

Hệ thống ATI **ĐÃ ĐƯỢC THIẾT KẾ ĐẶC BIỆT** cho Cyber Threat Intelligence. Kiến trúc hiện tại:
- ✅ Đã có Neo4j Knowledge Graph (core/knowledge_graph.py)
- ✅ Đã có Threat Memory 5 tính năng (core/threat_memory.py)
- ✅ Đã có Graph Intelligence Layer với SPARQL-like queries (core/graph_intelligence_layer.py)
- ✅ Đã có Agent Memory Bridge (core/agent_memory_bridge.py)
- ✅ Đã có OpenCTI Integration (tools/opencti_client.py)
- ✅ Đã có NVD Integration (tools/nvd_client.py)
- ✅ Đã có Pattern Detection (core/pattern_detection.py)
- ✅ Đã có Historical Context (core/historical_context.py)

**MỤC ĐÍCH CỦA MCP VÀ GRAPHRAG**: Cung cấp giao diện công cụ và tìm kiếm tự nhiên cho các khả năng này, không phải thay thế.

---

## II. KIỂM KÊ TOÀN BỘ THÀNH PHẦN

### A. LỚPP GRAPH INTELLIGENCE (8 mô-đun, ~2500 LOC)

| Mô-đun | Mục đích | Phụ thuộc | Tái sử dụng |
|--------|---------|----------|-----------|
| **core/knowledge_graph.py** | Unified Threat Knowledge Graph, node/edge management, path traversal | Pydantic, dataclasses | Graph MCP + GraphRAG |
| **core/graph_intelligence_layer.py** | SPARQL-like queries, find_attack_paths_to, find_assets_affected_by | threat_repository, threat_schema | Graph MCP + GraphRAG |
| **core/graph_query_engine.py** | Query optimization, caching, pattern matching | knowledge_graph | Graph MCP + GraphRAG |
| **core/graph_integration.py** | Graph-aware operations, integration with agents | graph_query_engine, knowledge_graph | Graph MCP + GraphRAG |
| **core/community_detection.py** | Threat community clustering, infrastructure grouping | knowledge_graph | GraphRAG |
| **core/actor_profiling.py** | Threat actor profile building, TTP evolution | threat_memory, knowledge_graph | GraphRAG |
| **core/trend_analysis.py** | CVE/exploit/campaign trend analysis | temporal_intelligence, threat_memory | GraphRAG |
| **core/anomaly_detection.py** | Outlier detection, unusual pattern detection | knowledge_graph, trend_analysis | GraphRAG |

**Tái sử dụng chiến lược**: 
- Graph MCP sẽ **mở rộng** core/graph_intelligence_layer.py + core/knowledge_graph.py
- GraphRAG sẽ **tích hợp** với community_detection + actor_profiling + trend_analysis
- Không có code trùng lặp, chỉ tạo MCP wrappers

---

### B. LỚPP THREAT MEMORY (5 mô-đun, ~1800 LOC)

| Mô-đul | Mục đích | Phụ thuộc | Tái sử dụng |
|--------|---------|----------|-----------|
| **core/threat_memory.py** | 5 bộ nhớ: Recurring IOC, Campaign Persistence, Asset Exposure, Infrastructure Reuse, Attack Pattern | Pydantic, datetime | Threat Memory MCP |
| **core/agent_memory_bridge.py** | Cầu nối Agent↔Memory, memory-augmented reasoning | threat_memory, pattern_detection, historical_context | Threat Memory MCP + Agents |
| **core/temporal_intelligence.py** | Time-series analysis, activity windows, seasonal patterns | threat_memory | Threat Memory MCP + GraphRAG |
| **core/pattern_detection.py** | Pattern detection, recurring threat detection, trend extraction | threat_memory, temporal_intelligence | Threat Memory MCP + GraphRAG |
| **core/historical_context.py** | Historical threat analysis, actor profiling, risk context building | threat_memory, pattern_detection | Threat Memory MCP + GraphRAG |

**Tái sử dụng chiến lược**:
- Threat Memory MCP sẽ **mở rộng** core/threat_memory.py + core/agent_memory_bridge.py
- Agent Memory Bridge là **điểm tích hợp** với LangGraph agents
- Temporal, Pattern, Historical là **công cụ hỗ trợ** cho Memory MCP
- Zero code duplication, chỉ thêm MCP transport layer

---

### C. LỚPP INTELLIGENCE CORE (10 mô-đul, ~3000 LOC)

| Mô-đul | Mục đích | Phụ thuộc | Tái sử dụng |
|--------|---------|----------|-----------|
| **core/threat_schema.py** | Canonical Pydantic models (CVE, IOC, Asset, Malware, Campaign, Actor, etc.) | Pydantic, enum | Toàn bộ hệ thống |
| **core/threat_repository.py** | Repository pattern interface, TTL management, freshness checking | threat_schema | SQLite + Neo4j backends |
| **core/sqlite_repository.py** | SQLite implementation | threat_repository, threat_schema | Offline persistence |
| **core/neo4j_repository.py** | Neo4j graph implementation | threat_repository, threat_schema | Future scaling |
| **core/threat_fusion.py** | Multi-source fusion (NVD, EPSS, KEV, Vulners) | threat_schema, enrichment providers | Enrichment pipeline |
| **core/threat_enrichment_pipeline.py** | Dynamic enrichment strategy selection | threat_fusion, threat_repository | Enrichment pipeline |
| **core/threat_correlation.py** | Relationship discovery (CVE↔Asset, IOC↔Malware) | threat_schema, threat_repository | Graph Intelligence + Assets |
| **core/threat_graph_analyzer.py** | Attack path analysis, infrastructure mapping | threat_correlation, threat_schema | Graph Intelligence + Assets |
| **core/threat_adapters.py** | Source adapters (NVD, EPSS, KEV, Vulners, OpenCTI) | threat_schema | Enrichment providers |
| **core/relationship_builders.py** | Relationship construction and validation | threat_schema, threat_repository | Relationship persistence |

**Tái sử dụng chiến lược**:
- **Không sửa đổi**, toàn bộ sẽ được **bảo tồn**
- Asset MCP sẽ **tái sử dụng** threat_correlation + threat_graph_analyzer
- Vulnerability MCP sẽ **tái sử dụng** threat_fusion + enrichment_pipeline
- IOC MCP sẽ **tái sử dụng** threat_adapters + OpenCTI integration

---

### D. LỚPP TOOLS & ENRICHMENT (20 mô-đul, ~2500 LOC)

| Mô-đul | Mục đích | Phụ thuộc | Tái sử dụng |
|--------|---------|----------|-----------|
| **tools/nvd_client.py** | NVD API integration | requests, asyncio | Vulnerability MCP |
| **tools/opencti_client.py** | OpenCTI GraphQL client, IOC/malware search | requests, regex | IOC MCP + Threat Memory |
| **tools/cwe_mapper.py** | CWE→MITRE ATT&CK mapping (802 CWEs) | threat_schema | Vulnerability MCP + Analysis |
| **tools/cmdb.py** | CMDB asset correlation, normalization | threat_schema | Asset MCP |
| **tools/report_generator.py** | Markdown/JSON/HTML report generation | threat_schema | Output layer |
| **tools/remediation_framework.py** | 50+ NIST control actions | threat_schema | Remediation layer |
| **tools/ioc_extractor.py** | IOC pattern extraction from text | regex, collections | IOC MCP + Log MCP |
| **tools/analyzer.py** | Multi-source analysis orchestration | threat_schema, enrichment | Analysis pipeline |
| **tools/kb_populator.py** | Knowledge base initialization | threat_repository | Data loading |
| **tools/relationship_validator.py** | Relationship validation and confidence | threat_schema | Relationship persistence |
| **tools/relationship_formatter.py** | Relationship output formatting | threat_schema | Output formatting |
| **tools/relationship_confidence_engine.py** | Confidence scoring with evidence | threat_schema | Relationship scoring |
| **tools/cve_relationship_tool.py** | CVE relationship queries | threat_repository | Vulnerability MCP |
| **tools/opencti_relationship_enricher.py** | Relationship enrichment from OpenCTI | opencti_client, threat_schema | IOC MCP |
| **tools/cve_relationship_integrator.py** | Multi-source relationship merging | threat_schema | Relationship integration |
| **tools/neo4j_relationship_persister.py** | Neo4j relationship persistence | neo4j, threat_schema | Graph persistence |
| **tools/product_extractor.py** | Software inventory extraction | regex | Asset MCP + CMDB |
| **tools/date_validator.py** | Date range validation | datetime | Log MCP + Input validation |
| **tools/doc_store.py** | Document storage and retrieval | pathlib | Document management |
| **tools/multi_source_intel.py** | Multi-source intelligence aggregation | threat_schema | Analysis pipeline |

**Tài sản Enrichment Provider** (5 mô-đul):
- tools/providers/base.py
- tools/providers/nvd_provider.py  
- tools/providers/epss_provider.py
- tools/providers/kev_provider.py
- tools/providers/vulncheck_provider.py
- tools/providers/vulners_provider.py

**Tài sản Enrichment Infrastructure** (3 mô-đul):
- tools/enrichment/schema.py
- tools/enrichment/cache.py
- tools/enrichment/orchestrator.py

**Tái sử dụng chiến lược**:
- Providers sẽ được **bảo tồn**, MCP sẽ **bao bọc** chúng
- NVD/OpenCTI clients là **điểm tích hợp** cho IOC + Vulnerability MCPs
- CWE mapper là **tài sản chung** cho tất cả phân tích
- Relationship tools sẽ **tái sử dụng** trong Graph MCP

---

### E. LỚPP AGENT ORCHESTRATION (3 mô-đul, ~1500 LOC)

| Mô-đul | Mục đích | Phụ thuộc | Tái sử dụng |
|--------|---------|----------|-----------|
| **agents/base.py** | 8 agent profiles, supervisor routing, TOOL_PERMISSIONS | threat_schema, tools/* | Không sửa đổi |
| **core/graph.py** | LangGraph StateGraph construction, routing logic | langgraph, agents/base | Không sửa đổi |
| **core/state.py** | CyberSecState TypedDict, state management | typing | Không sửa đổi |

**Tái sử dụng chiến lược**:
- **Bảo tồn hoàn toàn**, không sửa đổi orchestration logic
- MCP sẽ được **gọi bởi agents** thông qua tools registry
- Agent Memory Bridge là **điểm tích hợp duy nhất** với threat_memory

---

### F. LỚPP INFRASTRUCTURE & ANALYSIS (8 mô-đul, ~1200 LOC)

| Mô-đul | Mục đích | Phụ thuộc | Tái sử dụng |
|--------|---------|----------|-----------|
| **core/threat_intelligence_reasoner.py** | Contextual threat reasoning | threat_schema, threat_memory | GraphRAG + Analysis |
| **core/decision_support.py** | Decision automation, recommendations | threat_schema | Analysis pipeline |
| **core/response_automation.py** | Action automation, playbooks | threat_schema | Remediation layer |
| **core/ollama_llm.py** | Local Ollama LLM integration | ollama, asyncio | GraphRAG reasoner |
| **core/advanced_analytics.py** | ML-based analytics, scoring | numpy, scikit-learn | GraphRAG enhancement |
| **core/system_health.py** | Monitoring, diagnostics, health checks | threat_repository | System monitoring |
| **core/migrations/manager.py** | Schema migrations, versioning | sqlite3 | Database management |
| **core/migrations/migration_001.py** | Schema migration example | threat_schema | Database management |

**Tái sử dụng chiến lStrategy**:
- ollama_llm là **nền tảng** cho GraphRAG reasoning layer
- threat_intelligence_reasoner sẽ **tái sử dụng** trong GraphRAG
- System health sẽ được **mở rộng** cho log MCP monitoring

---

## III. PHÂN TÍCH PHỤ THUỘC LIÊN HỆ

### Hub Cốt Lõi (Độ phụ thuộc cao):

```
threat_schema.py
  ↑ (imported by 20+ modules)
  ├─ core/threat_repository.py
  ├─ core/threat_fusion.py
  ├─ core/threat_correlation.py
  ├─ core/knowledge_graph.py
  ├─ core/threat_memory.py
  ├─ all tools/*
  └─ all agents/*

threat_memory.py
  ↑ (imported by 8 modules)
  ├─ core/agent_memory_bridge.py
  ├─ core/pattern_detection.py
  ├─ core/historical_context.py
  ├─ tools/opencti_relationship_enricher.py
  └─ agents (potentially)

knowledge_graph.py
  ↑ (imported by 6 modules)
  ├─ core/graph_intelligence_layer.py
  ├─ core/graph_query_engine.py
  ├─ core/graph_integration.py
  ├─ core/community_detection.py
  ├─ core/actor_profiling.py
  └─ tools/neo4j_relationship_persister.py

threat_repository.py
  ↑ (imported by 8+ modules)
  ├─ core/threat_enrichment_pipeline.py
  ├─ core/threat_correlation.py
  ├─ core/threat_graph_analyzer.py
  ├─ core/graph_intelligence_layer.py
  ├─ core/sqlite_repository.py
  ├─ core/neo4j_repository.py
  └─ tools/kb_populator.py
```

**Hàm ý**: Không sửa đổi các hub này. Tất cả tích hợp MCP phải:
- Tái sử dụng chúng qua import
- Không sao chép code
- Không tạo wrappers dư thừa

---

## IV. ĐÁNH GIÁ KHẢ NĂNG TÁI SỬ DỤNG CHO TỪNG MCP

### Graph MCP

**Thành phần tái sử dụng**:
- ✅ core/knowledge_graph.py (GraphNode, GraphEdge, KnowledgeGraph class)
- ✅ core/graph_intelligence_layer.py (SPARQL-like query interface)
- ✅ core/graph_query_engine.py (query optimization)
- ✅ core/threat_correlation.py (relationship discovery)
- ✅ core/threat_graph_analyzer.py (attack path analysis)

**Cách triển khai**:
```
Graph MCP Server
  └─ Wraps core/knowledge_graph.py
  └─ Exposes: add_node, add_edge, query, find_paths, find_communities
  └─ Uses: core/graph_intelligence_layer.py for advanced queries
  └─ Integration: Agents call via tools registry
```

**Độ phức tạp**: TRUNG BÌNH (1-2 tuần)  
**Đề xuất ưu tiên**: **1 (FIRST)**

---

### Threat Memory MCP

**Thành phần tái sử dụng**:
- ✅ core/threat_memory.py (5 memory types)
- ✅ core/agent_memory_bridge.py (agent integration)
- ✅ core/pattern_detection.py (pattern extraction)
- ✅ core/historical_context.py (context building)
- ✅ core/temporal_intelligence.py (timeline analysis)

**Cách triển khai**:
```
Threat Memory MCP Server
  └─ Wraps core/threat_memory.py
  └─ Exposes: record_observation, get_ioc_memory, get_campaign_memory, etc.
  └─ Uses: core/agent_memory_bridge.py for agent queries
  └─ Integration: Agents access via tools registry
```

**Độ phức tạp**: TRUNG BÌNH (1-2 tuần)  
**Đề xuất ưu tiên**: **2 (SECOND)**

---

### Asset MCP

**Thành phần tái sử dụng**:
- ✅ core/threat_correlation.py (asset-CVE correlation)
- ✅ core/threat_graph_analyzer.py (infrastructure mapping)
- ✅ tools/cmdb.py (asset management)
- ✅ tools/product_extractor.py (software inventory)
- ✅ core/threat_repository.py (asset persistence)

**Cách triển khai**:
```
Asset MCP Server
  └─ Wraps tools/cmdb.py
  └─ Exposes: get_asset, query_assets, correlate_vulnerabilities
  └─ Uses: core/threat_correlation.py for CVE matching
  └─ Integration: Agents call for asset operations
```

**Độ phức tạp**: TRUNG BÌNH (1-2 tuần)  
**Đề xuất ưu tiên**: **3 (THIRD)**

---

### OpenCTI MCP

**Thành phần tái sử dụng**:
- ✅ tools/opencti_client.py (GraphQL client)
- ✅ tools/opencti_relationship_enricher.py (relationship enrichment)
- ✅ tools/ioc_extractor.py (pattern extraction)
- ✅ tools/analyzer.py (multi-source analysis)
- ✅ core/threat_correlation.py (correlation logic)

**Cách triển khai**:
```
OpenCTI MCP Server
  └─ Wraps tools/opencti_client.py
  └─ Exposes: search_indicators, search_malware, search_campaigns, search_actors
  └─ Uses: tools/opencti_relationship_enricher.py for enrichment
  └─ Integration: Agents call for IOC operations
```

**Độ phức tạp**: THẤP (1 tuần)  
**Đề xuất ưu tiên**: **4 (FOURTH)**

---

### Vulnerability MCP

**Thành phần tái sử dụng**:
- ✅ tools/nvd_client.py (NVD API)
- ✅ core/threat_fusion.py (multi-source fusion)
- ✅ core/threat_enrichment_pipeline.py (enrichment strategy)
- ✅ tools/cwe_mapper.py (CWE mapping)
- ✅ tools/cve_relationship_tool.py (CVE relationships)

**Cách triển khai**:
```
Vulnerability MCP Server
  └─ Wraps tools/nvd_client.py
  └─ Exposes: get_cve, search_cves, enrich_cve, get_cwe_info
  └─ Uses: core/threat_fusion.py for enrichment
  └─ Integration: Agents call for CVE operations
```

**Độ phức tạp**: THẤP (1 tuần)  
**Đề xuất ưu tiên**: **5 (FIFTH)**

---

### IOC MCP

**Thành phần tái sử dụng**:
- ✅ tools/ioc_extractor.py (pattern extraction)
- ✅ tools/opencti_client.py (OpenCTI search)
- ✅ tools/analyzer.py (analysis)
- ✅ tools/relationship_confidence_engine.py (scoring)
- ✅ core/threat_correlation.py (correlation)

**Cách triển khai**:
```
IOC MCP Server
  └─ Wraps tools/ioc_extractor.py + tools/opencti_client.py
  └─ Exposes: extract_iocs, search_ioc, get_ioc_context
  └─ Uses: OpenCTI client for enrichment
  └─ Integration: Agents call for IOC operations
```

**Độ phức tạp**: THẤP (1 tuần)  
**Đề xuất ưu tiên**: **6 (SIXTH)**

---

### Log MCP

**Thành phần tái sử dụng**:
- ✅ tools/ioc_extractor.py (pattern extraction from logs)
- ✅ tools/date_validator.py (time filtering)
- ✅ tools/analyzer.py (log analysis)
- ✅ core/pattern_detection.py (threat pattern detection)
- ✅ core/historical_context.py (temporal context)

**Cách triển khai**:
```
Log MCP Server
  └─ New implementation (no duplication)
  └─ Exposes: parse_logs, extract_iocs, detect_anomalies, get_timeline
  └─ Uses: tools/ioc_extractor.py for pattern extraction
  └─ Uses: core/pattern_detection.py for threat detection
  └─ Integration: Agents ingest logs for analysis
```

**Độ phức tạp**: TRUNG BÌNH (1-2 tuần)  
**Đề xuất ưu tiên**: **7 (SEVENTH)**

---

### GraphRAG

**Thành phần tái sử dụng**:
- ✅ core/knowledge_graph.py (graph storage)
- ✅ core/threat_memory.py (contextual memory)
- ✅ core/community_detection.py (clustering)
- ✅ core/actor_profiling.py (profiling)
- ✅ core/trend_analysis.py (trend analysis)
- ✅ core/threat_intelligence_reasoner.py (reasoning)
- ✅ core/ollama_llm.py (local LLM)
- ✅ core/advanced_analytics.py (analytics)

**Cách triển khai**:
```
GraphRAG System
  └─ Enhancer (not replacement) of Graph Intelligence Layer
  └─ Adds: Natural language reasoning over graph
  └─ Uses: core/ollama_llm.py for local LLM
  └─ Uses: core/knowledge_graph.py for entity/relationship retrieval
  └─ Uses: core/threat_memory.py for temporal context
  └─ Integration: Agents can query via natural language
```

**Độ phức tạp**: CAO (3-4 tuần)  
**Đề xuất ưu tiên**: **8 (LAST - after other MCPs)**

---

## V. CHIẾN LƯỢC TÍCH HỢP KHÔNG PHƯƠNG NGOẠI

### Nguyên tắc cốt lõi:

1. **BẢOCC TOÀN**: Không sửa đổi core/agents, core/graph, core/state
2. **TÁI SỬ DỤNG**: Mọi MCP phải import từ core/, không copy-paste
3. **WRAPPER PATTERN**: Mỗi MCP = MCP Server + Tool Wrapper
4. **TOOL REGISTRY**: Agents gọi MCPs qua TOOL_PERMISSIONS
5. **OFFLINE FIRST**: Tất cả MCPs hoạt động offline, không API call

### Mô hình tích hợp MCP:

```
┌─────────────────────────────────────────────┐
│          LangGraph Agents                    │
│  (agents/base.py + 8 agent profiles)        │
└──────────────────┬──────────────────────────┘
                   │
                   ├─ TOOL_PERMISSIONS
                   │   └─ Map agent → MCP tools
                   │
     ┌─────────────▼─────────────┐
     │   MCP Tools Registry       │
     │   (tools/mcp_*.py)         │
     └─────────────┬─────────────┘
                   │
        ┌──────────┼──────────┬──────────┬──────────┐
        │          │          │          │          │
    [Graph MCP] [Memory MCP] [Asset MCP] [IOC MCP] [Vuln MCP]
        │          │          │          │          │
        └──────────┼──────────┼──────────┼──────────┘
                   │
        ┌──────────▼──────────┐
        │  Core Libraries      │
        │  (core/*.py, tools/*)|
        └─────────────────────┘
                   │
        ┌──────────▼──────────┐
        │  Persistence Layer   │
        │  (SQLite/Neo4j)      │
        └─────────────────────┘
```

### Quy trình thêm MCP:

1. **Tạo wrapper** tools/mcp_<name>.py
2. **Import core libs** (không copy code)
3. **Định nghĩa schema** của MCP tools
4. **Thêm vào tools registry** → TOOL_PERMISSIONS
5. **Agents gọi nó** như công cụ thông thường

### Ví dụ (Graph MCP):

```python
# tools/mcp_graph.py
from core.knowledge_graph import KnowledgeGraph
from core.graph_intelligence_layer import GraphIntelligenceLayer

class GraphMCPServer:
    def __init__(self, repository):
        self.graph = KnowledgeGraph()
        self.intelligence = GraphIntelligenceLayer(repository)
    
    def add_node(self, node_id, node_type, properties):
        """MCP: Add node to knowledge graph"""
        return self.graph.add_node(node_id, node_type, properties)
    
    def find_attack_paths(self, target_asset, min_severity, max_depth):
        """MCP: SPARQL-like query for attack paths"""
        return self.intelligence.find_attack_paths_to(
            target_asset, min_severity, max_depth
        )
```

Agents gọi:
```python
# agents/base.py
{
    "agent_ti": {
        "tools": ["graph_add_node", "graph_find_paths", ...]
    }
}
```

---

## VI. PHÂN TÍCH RỦI RO TÍCH HỢP

### Risk: Circular Dependencies

**Rủi ro**: Graph MCP imports threat_memory, Threat Memory MCP imports knowledge_graph  
**Giải pháp**: Tách giao diện, dùng repository pattern  
**Mức độ**: THẤP (quản lý được)

### Risk: Performance Degradation

**Rủi ro**: N MCPs × Agent calls = N² queries  
**Giải pháp**: Implement caching tại MCP level  
**Mức độ**: TRUNG BÌNH (khắc phục bằng optimization)

### Risk: State Inconsistency

**Rủi ro**: Multiple MCPs viết graph/memory đồng thời  
**Giải pháp**: Implement locking, transaction semantics  
**Mức độ**: TRUNG BÌNH (chuẩn database)

### Risk: Offline Compatibility

**Rủi ro**: MCPs require internet APIs  
**Giải pháp**: Ensure all MCPs work with local-only data  
**Mức độ**: THẤP (kiến trúc đã offline-first)

---

## VII. LỘTRÌNH TRIỂN KHAI ĐƯỢC KHUYẾN NGHỊ

### Phase 1: Graph MCP (Tuần 1-2)
- **Output**: tools/mcp_graph.py + 4 tools
- **Reuse**: core/knowledge_graph.py, core/graph_intelligence_layer.py
- **Risk**: THẤP
- **Value**: CAO (SPARQL-like queries for agents)

### Phase 2: Threat Memory MCP (Tuần 3-4)
- **Output**: tools/mcp_threat_memory.py + 6 tools
- **Reuse**: core/threat_memory.py, core/agent_memory_bridge.py
- **Risk**: THẤP
- **Value**: CAO (persistent memory across runs)

### Phase 3: Asset MCP (Tuần 5-6)
- **Output**: tools/mcp_asset.py + 5 tools
- **Reuse**: tools/cmdb.py, core/threat_correlation.py
- **Risk**: TRUNG BÌNH
- **Value**: CAO (asset exposure analysis)

### Phase 4: OpenCTI MCP (Tuần 7)
- **Output**: tools/mcp_opencti.py + 5 tools
- **Reuse**: tools/opencti_client.py
- **Risk**: THẤP
- **Value**: TRUNG BÌNH (IOC enrichment)

### Phase 5: Vulnerability MCP (Tuần 8)
- **Output**: tools/mcp_vulnerability.py + 5 tools
- **Reuse**: tools/nvd_client.py, core/threat_fusion.py
- **Risk**: THẤP
- **Value**: CAO (CVE enrichment)

### Phase 6: IOC MCP (Tuần 9)
- **Output**: tools/mcp_ioc.py + 4 tools
- **Reuse**: tools/ioc_extractor.py
- **Risk**: THẤP
- **Value**: TRUNG BÌNH (IOC analysis)

### Phase 7: Log MCP (Tuần 10-11)
- **Output**: tools/mcp_log.py + 5 tools
- **Reuse**: tools/ioc_extractor.py, core/pattern_detection.py
- **Risk**: TRUNG BÌNH
- **Value**: CAO (log analysis + threat detection)

### Phase 8: GraphRAG (Tuần 12-15)
- **Output**: core/graphrag_layer.py + MCP integration
- **Reuse**: 8+ core modules (graph, memory, analysis, ollama)
- **Risk**: CAO (reasoning complexity)
- **Value**: RẤT CAO (NLP over threat graph)

---

## VIII. KHUYẾN NGHỊ CUỐI CÙNG

### ✅ ĐƯỢC PHỀ DUYỆT:

1. **Giữ kiến trúc hiện tại** - Rất tốt cho CTI
2. **Tạo MCP wrappers** - Không breaking changes
3. **Thực hiện theo Phase** - Kiểm soát độ phức tạp
4. **Ưu tiên Graph → Memory → Assets** - Giá trị cao nhất trước
5. **Defer GraphRAG** - Cho đến khi các MCPs ổn định

### ⚠️ CẢNH BÁO:

1. **Không copy-paste code** - Tất cả MCPs import core/
2. **Không sửa agents/base.py** - Bảo tồn orchestration
3. **Không bỏ bất kỳ core module nào** - Sẽ có dependencies cụm
4. **Đảm bảo offline** - Không external APIs
5. **Test tích hợp** - MCPs + Agents phải hoạt động cùng nhau

### 📊 METRIC THÀNH CÔNG:

- ✅ Zero code duplication (reuse rate >90%)
- ✅ Agents không cần modify (orchestration unchanged)
- ✅ All MCPs work offline (no external APIs)
- ✅ Performance <2s per agent tool call
- ✅ Tests pass 100% (integration + unit tests)

---

## IX. KẾT LUẬN

Hệ thống ATI **đã sẵn sàng** cho quá trình MCP + GraphRAG:

| Khía cạnh | Trạng thái | Ghi chú |
|-----------|-----------|--------|
| Knowledge Graph | ✅ Có | core/knowledge_graph.py |
| Threat Memory | ✅ Có | core/threat_memory.py + 5 types |
| Agent Integration | ✅ Có | core/agent_memory_bridge.py |
| Graph Intelligence | ✅ Có | SPARQL-like queries |
| OpenCTI Integration | ✅ Có | tools/opencti_client.py |
| NVD Integration | ✅ Có | tools/nvd_client.py |
| Pattern Detection | ✅ Có | core/pattern_detection.py |
| Historical Context | ✅ Có | core/historical_context.py |
| Offline Support | ✅ Có | SQLite + Neo4j backends |
| LLM Integration | ✅ Có | core/ollama_llm.py |

**Không phải rebuild - mà là refactor + extend để khai thác tối đa.**

---

**PHASE 0 AUDIT HOÀN THÀNH**

**Sẵn sàng cho PHASE 1: Detailed Implementation Plan**

**Phê duyệt cần thiết từ Principal Engineer trước khi tiếp tục.**
