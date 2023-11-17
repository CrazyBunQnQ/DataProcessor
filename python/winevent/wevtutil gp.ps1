# ���峣�� save_path �� windows_version
$save_path = "D:\GitProjects\DataProcessor\python\winevent\input"
# $windows_version = (Get-WmiObject -Class Win32_OperatingSystem).Version
# $windows_version = (Get-WmiObject -Class Win32_OperatingSystem).Caption
$windows_version = "windows11"

# ִ�� wevtutil ep ����������� publisher_names �б�
$publisher_names = wevtutil ep

# �����־
Write-Host "��ȡ���� Publisher Names �б�: "
Write-Host $publisher_names

# ���� publisher_names �е�ÿ�� name
foreach ($name in $publisher_names) {
    # �����־
    Write-Host "���ڴ��� Publisher Name: $name"

    # ִ�� wevtutil gp �����������浽�ļ�
    $outputFile = "${save_path}\${name}_${windows_version}.txt"
    # ����ļ������ڣ��򴴽��ļ�
    if (-not (Test-Path -Path $outputFile)) {
        New-Item -Path $outputFile -ItemType File
        Write-Host "�ļ��Ѵ���: $outputFile"
    }
    wevtutil gp "${name}" /ge /gm:true | Out-File -FilePath $outputFile -Append -Encoding UTF8

    # �����־
    Write-Host "����ѱ��浽: $outputFile"
}

# ��ɽű��������־
Write-Host "���� Publisher Names �Ѵ������"