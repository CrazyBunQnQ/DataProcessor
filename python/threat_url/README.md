### 更新威胁URL知识库说明

从系统中导出威胁URL知识库保存到当前目录，文件名 threat_urls.rule

执行 base64_processor.py 解密 threat_urls.rule 文件

```bash
python base64_processor.py threat_urls.rule
```

生成解密后的文件 threat_urls.json

执行 threat_url_processor.py 更新 threat_urls.json 文件

```bash
python threat_url_processor.py
```

执行 threat_url_processor.py 加密 threat_urls.json 文件

```bash
python base64_processor.py threat_urls.json
```
