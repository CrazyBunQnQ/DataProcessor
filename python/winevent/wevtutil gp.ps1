# 定义常量 save_path 和 windows_version
$save_path = "D:\GitProjects\DataProcessor\python\winevent\input"
# $windows_version = (Get-WmiObject -Class Win32_OperatingSystem).Version
# $windows_version = (Get-WmiObject -Class Win32_OperatingSystem).Caption
$windows_version = "windows11"

# 执行 wevtutil ep 命令输出所有 publisher_names 列表
$publisher_names = wevtutil ep

# 输出日志
Write-Host "获取到的 Publisher Names 列表: "
Write-Host $publisher_names

# 遍历 publisher_names 中的每个 name
foreach ($name in $publisher_names) {
    # 输出日志
    Write-Host "正在处理 Publisher Name: $name"

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