#!/usr/bin/env python
"""
setup_data_protection.py - Bảo vệ thư mục data/ khỏi truy cập trực tiếp

Làm cho chỉ có ứng dụng ATI có thể truy cập dữ liệu nội bộ.
Người dùng chỉ có thể tương tác thông qua menu ứng dụng.

Trên Windows: Đặt NTFS ACL - Chỉ Administrator/System có thể truy cập
Trên Linux/Mac: Đặt chmod 700 (rwx------)

Cách sử dụng:
  python setup_data_protection.py

Hoặc từ PowerShell (Windows, cần Admin):
  powershell -ExecutionPolicy Bypass -File .\setup_data_protection.ps1
"""

import os
import sys
import platform
from pathlib import Path

DATA_FOLDER = Path("data")

def setup_windows():
    """Bảo vệ folder trên Windows bằng NTFS ACL."""
    import subprocess

    print("Setting up Windows NTFS protection...")
    print()

    # Kiểm tra admin
    try:
        import ctypes
        is_admin = ctypes.windll.shell.IsUserAnAdmin()
    except:
        is_admin = False

    if not is_admin:
        print("ERROR: Cần chạy với quyền Administrator")
        print("Hãy mở Command Prompt/PowerShell với quyền Admin và chạy lại")
        return False

    try:
        abs_path = DATA_FOLDER.absolute()

        # PowerShell script để set ACL
        ps_cmd = f"""
$ErrorActionPreference = 'Stop'
$folder = '{abs_path}'

# Lấy ACL hiện tại
$acl = Get-Acl $folder

# Ngừng kế thừa quyền từ parent folder
$acl.SetAccessRuleProtection($true, $false)

# Xóa tất cả quy tắc hiện tại
$acl.Access | ForEach-Object {{
    $acl.RemoveAccessRule($_)
}}

# Chỉ cho phép SYSTEM và Administrators
$systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    'NT AUTHORITY\\SYSTEM',
    'FullControl',
    'ContainerInherit,ObjectInherit',
    'None',
    'Allow'
)

$adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    'BUILTIN\\Administrators',
    'FullControl',
    'ContainerInherit,ObjectInherit',
    'None',
    'Allow'
)

$acl.AddAccessRule($systemRule)
$acl.AddAccessRule($adminRule)

# Áp dụng ACL
Set-Acl -Path $folder -AclObject $acl

Write-Host 'ACL configured successfully'
"""

        result = subprocess.run(
            ['powershell', '-NoProfile', '-Command', ps_cmd],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode != 0:
            print(f"Error: {result.stderr}")
            return False

        print("[SUCCESS] Quyền NTFS được cấu hình")
        print(f"Folder: {abs_path}")
        print()
        print("Quyền truy cập:")
        print("  - NT AUTHORITY\\SYSTEM: Full Control")
        print("  - BUILTIN\\Administrators: Full Control")
        print("  - Người dùng khác: TỪCHỐI")
        print()

        return True

    except Exception as e:
        print(f"ERROR: {e}")
        return False

def setup_unix():
    """Bảo vệ folder trên Linux/Mac bằng chmod."""
    print("Setting up Unix file permissions...")
    print()

    try:
        abs_path = DATA_FOLDER.absolute()

        # 0o700 = rwx------ (chỉ owner)
        os.chmod(abs_path, 0o700)

        # Recursive cho tất cả subfolder
        for root, dirs, files in os.walk(abs_path):
            for d in dirs:
                os.chmod(os.path.join(root, d), 0o700)
            for f in files:
                os.chmod(os.path.join(root, f), 0o600)

        print("[SUCCESS] File permissions được cấu hình")
        print(f"Folder: {abs_path}")
        print()
        print("Quyền truy cập:")
        print("  - Thư mục: 700 (rwx------)")
        print("  - File: 600 (rw-------)")
        print()

        return True

    except Exception as e:
        print(f"ERROR: {e}")
        return False

def main():
    print("=" * 70)
    print("DATA FOLDER PROTECTION - BAO VE DU LIEU NOI BO")
    print("=" * 70)
    print()

    if not DATA_FOLDER.exists():
        print(f"ERROR: Không tìm thấy folder: {DATA_FOLDER.absolute()}")
        return False

    print(f"Bảo vệ: {DATA_FOLDER.absolute()}")
    print()
    print("Mục đích: Chỉ ứng dụng ATI có thể truy cập dữ liệu")
    print("Người dùng tương tác thông qua menu ứng dụng")
    print()

    system = platform.system()

    if system == "Windows":
        success = setup_windows()
    elif system in ("Linux", "Darwin"):
        success = setup_unix()
    else:
        print(f"ERROR: Hệ điều hành không được hỗ trợ: {system}")
        return False

    if success:
        print("=" * 70)
        print("HOAN TAT - DU LIEU DA DUOC BAO VE")
        print("=" * 70)
        print()
        print("Người dùng chỉ có thể truy cập qua:")
        print("  - Menu 1: Tìm kiếm CVE")
        print("  - Menu 2: Báo cáo CVE")
        print("  - Menu 3: Upload tài liệu IOC/Malware")
        print("  - Menu 4: Truy vấn thiết bị")
        print("  - Menu 5: Cài đặt quản trị")
        print()
        return True
    else:
        print("=" * 70)
        print("FAILED - BAO VE THAT BAI")
        print("=" * 70)
        print()
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
