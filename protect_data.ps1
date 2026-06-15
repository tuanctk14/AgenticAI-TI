# protect_data.ps1
# Bảo vệ thư mục data/ - chỉ Admin có thể xem/chỉnh sửa

param()

$folder = (Get-Item "data").FullName

Write-Host "Applying NTFS protection to: $folder"
Write-Host ""

# Lấy ACL hiện tại
$acl = Get-Acl $folder

# Ngừng kế thừa quyền từ parent folder
$acl.SetAccessRuleProtection($true, $false)

# Xóa tất cả quy tắc hiện tại
foreach ($rule in $acl.Access) {
    $acl.RemoveAccessRule($rule) | Out-Null
}

# Chỉ cho phép SYSTEM
$systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "NT AUTHORITY\SYSTEM",
    "FullControl",
    "ContainerInherit,ObjectInherit",
    "None",
    "Allow"
)

# Chỉ cho phép Administrators
$adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "BUILTIN\Administrators",
    "FullControl",
    "ContainerInherit,ObjectInherit",
    "None",
    "Allow"
)

$acl.AddAccessRule($systemRule)
$acl.AddAccessRule($adminRule)

# Áp dụng ACL
Set-Acl -Path $folder -AclObject $acl

Write-Host "[SUCCESS] Folder data/ protected"
Write-Host ""
Write-Host "Access permissions:"
Write-Host "  - NT AUTHORITY\SYSTEM: Full Control"
Write-Host "  - BUILTIN\Administrators: Full Control"
Write-Host "  - Other users: DENIED"
Write-Host ""
Write-Host "Current ACL:"
Get-Acl $folder | Format-List
