### 更新

下载数据放到 data 目录

根据代码中现有数据路径

existing_data_file = r"E:\LaProjects\dev\Singularity\framework\framework\src\main\resources\resources\knowledgeBase\CVE.json"

执行 python .\cve_processor.py

生成增量文件

CVE_incremental_*.json

使用能编辑大文件的文本编辑器将新增数据粘贴到现有数据文件中

### 翻译

-o 输出文件
--cache-file 翻译缓存
后续跟需要翻译与合并的文件
python cve_full_generator.py -o CVE_full_20251208.json --cache-file translate_cache.jsonl CVE_incremental_20251205.json E:\LaProjects\dev\Singularity\framework\framework\src\main\resources\resources\knowledgeBase\CVE_svn60382.json

#### 处理错误的翻译缓存

移除错误翻译

{"key":.*transla.*\n
{"key":.*English.*\n
{"key":.*posted by.*\n
{"key": "([^"]{0,70})", "value": "[^"]{151,}"}\n

再次翻译

### 补全修复建议

进入 cve 目录

修改相关路径

```
rules_path = pathlib.Path(r'F:\OtherProjects\SuricataRules\rules.sugst')
input_path = base / 'CVE_full_20251205.json'
output_path = base / 'CVE_full_20251205_solution.json'
cache_path = base / 'solutions_cache.jsonl'
```

执行

python fill_solutions_from_rules.py