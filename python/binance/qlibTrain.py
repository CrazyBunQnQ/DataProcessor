import pandas as pd

# 读取并合并所有CSV文件
csv_files = [
    'path_to_your_data/processed_BAKEUSDT_20231105.csv',
    'path_to_your_data/processed_BSWUSDT_20231105.csv',
    'path_to_your_data/processed_CHZUSDT_20231105.csv',
    # ... 其他文件路径
]
combined_df = pd.concat((pd.read_csv(file) for file in csv_files), ignore_index=True)

# 确保时间戳的格式是正确的，并将其设置为索引
combined_df['Time'] = pd.to_datetime(combined_df['Time'])
combined_df.set_index('Time', inplace=True)

# 分离特征和目标变量
features = combined_df.drop(columns=['Expected_High_Increase', 'Expected_Low_Increase'])
targets = combined_df[['Expected_High_Increase', 'Expected_Low_Increase']]

# 保存处理后的特征和目标变量
features.to_csv('path_to_your_data/processed_features.csv')
targets.to_csv('path_to_your_data/processed_targets.csv')

# ############################

import qlib
from qlib.config import REG_CN
from qlib.data.dataset import DatasetH
from qlib.data.dataset.handler import DataHandlerLP
from qlib.contrib.model.pytorch_lstm import LSTMModel
from qlib.contrib.data.handler import QLibDataHandler
from qlib.contrib.estimator.handler import LGBModelHandler

# 初始化Qlib
qlib.init(provider_uri='./data', region=REG_CN)  # 设置你的数据提供者路径

# 加载特征和目标变量数据
features = pd.read_csv('path_to_your_data/processed_features.csv', index_col='datetime')
targets = pd.read_csv('path_to_your_data/processed_targets.csv', index_col='datetime')

# 定义数据处理器
handler_config = {
    "start_time": "2023-01-01",  # 根据你的数据设置合适的时间
    "end_time": "2023-12-31",    # 根据你的数据设置合适的时间
    "fit_start_time": "2023-01-01",  # 根据你的数据设置合适的时间
    "fit_end_time": "2023-10-31",    # 根据你的数据设置合适的时间
    "instruments": "csi1000"
}

# 创建数据集
dataset = DatasetH(
    handler=DataHandlerLP(data=features.join(targets)),
    segments=handler_config
)

# 定义LSTM模型
model = LSTMModel()

# 训练模型
model.fit(dataset)

# 保存模型
model.save('path_to_your_model/lstm_model.bin')

# 进行预测
pred = model.predict(dataset)
