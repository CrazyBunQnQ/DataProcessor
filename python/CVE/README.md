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

确保目录下存在 `.env` 文件配置了 `OPENAI_API_KEY`。

运行脚本：

```bash
python fill_solutions_from_rules.py
```

脚本会自动读取当前目录下的 `CVE_full_20251205.json`（如需修改输入文件请编辑脚本），并加载 `solutions_cache.jsonl` 缓存。
对于 `solution` 字段为空的数据：
1. 尝试在 `rules.sugst` 中匹配相关处置建议。
2. 若匹配成功，以建议为上下文生成修复方案（来源标记为 `suggest`）。
3. 若未匹配，直接根据漏洞描述生成修复方案（来源标记为 `AI`）。
4. 生成结果实时写入缓存，最终输出到 `CVE_full_20251205_solution.json`。

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