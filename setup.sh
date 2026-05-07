#!/usr/bin/env bash
# setup.sh - Cài đặt CyberSec Multi-Agent System (Ollama Local Edition)
# Chạy: bash setup.sh

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo ""
echo "🛡️  CyberSec Multi-Agent System — Setup"
echo "========================================"

# ── 1. Kiểm tra Python ────────────────────────────────────────────────────
echo -e "\n${YELLOW}[1/5] Kiểm tra Python...${NC}"
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}❌ Python 3 chưa được cài. Tải tại: https://python.org${NC}"
    exit 1
fi
PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo -e "${GREEN}✅ Python ${PY_VER}${NC}"

# ── 2. Kiểm tra Ollama ────────────────────────────────────────────────────
echo -e "\n${YELLOW}[2/5] Kiểm tra Ollama...${NC}"
if ! command -v ollama &>/dev/null; then
    echo -e "${YELLOW}⚠️  Ollama chưa được cài. Đang cài tự động...${NC}"
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        curl -fsSL https://ollama.com/install.sh | sh
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "  Tải Ollama tại: https://ollama.com/download/mac"
        echo "  Sau đó chạy lại script này."
        exit 1
    elif [[ "$OSTYPE" == "msys"* || "$OSTYPE" == "win32" ]]; then
        echo "  Tải Ollama tại: https://ollama.com/download/windows"
        echo "  Sau đó chạy lại script này."
        exit 1
    fi
fi
echo -e "${GREEN}✅ Ollama đã cài${NC}"

# ── 3. Pull model ─────────────────────────────────────────────────────────
echo -e "\n${YELLOW}[3/5] Chọn model Ollama...${NC}"
echo "  1) qwen2.5:7b   (~4GB RAM) - Tốt tiếng Việt ⭐ Khuyến nghị"
echo "  2) llama3.2:3b  (~2GB RAM) - Nhẹ nhất, nhanh"
echo "  3) llama3.1:8b  (~5GB RAM) - Cân bằng"
echo "  4) mistral:7b   (~4GB RAM) - Rất nhanh"
echo "  5) Bỏ qua (đã có model)"
read -p "  Chọn (1-5): " model_choice

case $model_choice in
    1) MODEL="qwen2.5:7b" ;;
    2) MODEL="llama3.2:3b" ;;
    3) MODEL="llama3.1:8b" ;;
    4) MODEL="mistral:7b" ;;
    5) MODEL="" ;;
    *) MODEL="qwen2.5:7b" ;;
esac

if [ -n "$MODEL" ]; then
    echo -e "${YELLOW}  Đang pull model ${MODEL}...${NC}"
    ollama pull "$MODEL"
    echo -e "${GREEN}  ✅ Model ${MODEL} đã sẵn sàng${NC}"
else
    # Detect model đã có
    MODEL=$(ollama list 2>/dev/null | awk 'NR>1{print $1; exit}')
    echo -e "${GREEN}  ✅ Dùng model hiện có: ${MODEL}${NC}"
fi

# ── 4. Cài Python packages ────────────────────────────────────────────────
echo -e "\n${YELLOW}[4/5] Cài Python packages...${NC}"
python3 -m pip install --upgrade pip -q
python3 -m pip install -r requirements.txt -q
echo -e "${GREEN}✅ Dependencies đã cài${NC}"

# ── 5. Tạo .env ───────────────────────────────────────────────────────────
echo -e "\n${YELLOW}[5/5] Tạo file .env...${NC}"
if [ ! -f .env ]; then
    cp .env.example .env
    # Cập nhật model trong .env
    sed -i "s/OLLAMA_MODEL=.*/OLLAMA_MODEL=${MODEL}/" .env 2>/dev/null || \
    sed -i '' "s/OLLAMA_MODEL=.*/OLLAMA_MODEL=${MODEL}/" .env  # macOS
    echo -e "${GREEN}✅ .env đã tạo (model: ${MODEL})${NC}"
else
    echo -e "${GREEN}✅ .env đã tồn tại${NC}"
fi

mkdir -p reports docs

# ── Xong ──────────────────────────────────────────────────────────────────
echo ""
echo "========================================"
echo -e "${GREEN}🎉 Cài đặt hoàn tất!${NC}"
echo ""
echo "Khởi động Ollama:    ollama serve"
echo "Chạy hệ thống:       python3 main.py"
echo "Kiểm tra kết nối:    python3 main.py --check"
echo "Test nhanh:          python3 main.py --test"
echo ""
