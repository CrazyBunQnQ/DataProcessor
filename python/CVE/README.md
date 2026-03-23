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

### 统一全流程脚本

脚本：`cve_unified_pipeline.py`

能力：
- 下载并解压XML数据（可选）
- 解析XML并与已有JSON输入合并去重
- 自动修正字段语言与补全缺失字段
- 自动补全修复建议并生成英文修复建议 `enSolution`
- 输出 `CVE_full_YYYYMMDD.json`

字段语言规则：
- `title`、`threatName` 为中文
- `enTitle`、`threatNameEng` 为英文
- `description` 为中文
- `vulnDescription`、`descriptionEng` 为英文
- `solution` 为中文，`enSolution` 为英文

示例1：仅处理已有输入文件

```bash
python cve_unified_pipeline.py --input-json CVE_incremental_20251205.json --output . --date-format %Y%m%d
```

示例2：下载后再处理

```bash
python cve_unified_pipeline.py --download-url "https://example.com/2026.xml" --download-url "https://example.com/cve_pack.zip" --input-json CVE_incremental_20251205.json --output .
```

常用参数：
- `--data-dir` XML数据目录，默认 `./data`
- `--download-url` 下载链接，可重复传入多个
- `--download-manifest` 文本文件路径，每行一个下载链接
- `--input-json` 需要合并的JSON文件列表
- `--rules-file` 规则文件，默认 `./rules.sugst`
- `--translate-cache` 翻译缓存文件，默认 `./translate_cache.jsonl`
- `--solution-cache` 修复建议缓存文件，默认 `./solutions_cache.jsonl`
- `--output` 输出目录或完整JSON文件路径
- `--date-format` 输出文件日期格式，默认 `%Y%m%d`
- `--log-level` 日志级别，默认 `INFO`
- `--debug` 开启调试模式

环境说明：
- Python 3.8+
- 若需自动翻译与自动生成修复建议，请在 `.env` 配置 `OPENAI_API_KEY`
