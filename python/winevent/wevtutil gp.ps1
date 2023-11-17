# ������Ҫ��ִ�� Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
# ���峣�� save_path �� windows_version
$save_path = "C:\events"
$windows_version_full = (Get-WmiObject -Class Win32_OperatingSystem).Caption
$windows_version_full = $windows_version_full.Replace("Server", "")
$windows_version = if ($windows_version_full -match "Windows\s+(\d+)") { "Windows$($matches[1])" } else { $windows_version }
Write-Host "��ǰϵͳ�汾Ϊ: $windows_version"

# ��� save_path Ŀ¼�Ƿ���ڣ���������ڣ��򴴽���
if (-not (Test-Path -Path $save_path)) {
    New-Item -Path $save_path -ItemType Directory
    Write-Host "Ŀ¼�Ѵ���: $save_path"
}

# ִ�� wevtutil ep ����������� publisher_names �б�
$publisher_names = wevtutil ep

# �����־
Write-Host "��ȡ���� Publisher Names �б�: "
Write-Host $publisher_names

# ���� publisher_names �е�ÿ�� name
foreach ($name in $publisher_names) {
    # �����־
    Write-Host "���ڴ��� Publisher Name: $name"
    # $name ���� '/' ʱ�滻Ϊ '-'
    $name = $name.Replace("/", "-")

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