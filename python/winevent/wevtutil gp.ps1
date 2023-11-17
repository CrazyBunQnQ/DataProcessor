# 可能需要先执行 Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
# 定义常量 save_path 和 windows_version
$save_path = "C:\events"
$windows_version_full = (Get-WmiObject -Class Win32_OperatingSystem).Caption
$windows_version_full = $windows_version_full.Replace("Server", "")
$windows_version = if ($windows_version_full -match "Windows\s+(\d+)") { "Windows$($matches[1])" } else { $windows_version }
Write-Host "当前系统版本为: $windows_version"

# 检查 save_path 目录是否存在，如果不存在，则创建它
if (-not (Test-Path -Path $save_path)) {
    New-Item -Path $save_path -ItemType Directory
    Write-Host "目录已创建: $save_path"
}

# 执行 wevtutil ep 命令输出所有 publisher_names 列表
$publisher_names = wevtutil ep

# 输出日志
Write-Host "获取到的 Publisher Names 列表: "
Write-Host $publisher_names

# 遍历 publisher_names 中的每个 name
foreach ($name in $publisher_names) {
    # 输出日志
    Write-Host "正在处理 Publisher Name: $name"
    # $name 包含 '/' 时替换为 '-'
    $name = $name.Replace("/", "-")

    # 执行 wevtutil gp 命令并将结果保存到文件
    $outputFile = "${save_path}\${name}_${windows_version}.txt"
    # 如果文件不存在，则创建文件
    if (-not (Test-Path -Path $outputFile)) {
        New-Item -Path $outputFile -ItemType File
        Write-Host "文件已创建: $outputFile"
    }
    wevtutil gp "${name}" /ge /gm:true | Out-File -FilePath $outputFile -Append -Encoding UTF8

    # 输出日志
    Write-Host "结果已保存到: $outputFile"
}

# 完成脚本的输出日志
Write-Host "所有 Publisher Names 已处理完成"