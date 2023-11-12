import os
import pandas as pd
from scipy.stats import zscore
from glob import glob
import pygwalker as pyg
from sklearn.model_selection import train_test_split
import numpy as np
import torch
import torch.nn as nn
import matplotlib.pyplot as plt
import datetime


# 计算 SMA 和 EMA
def calculate_moving_averages(data, short_window=5, long_window=10):
    data['SMA_5'] = data['Close'].rolling(window=short_window).mean()
    data['SMA_10'] = data['Close'].rolling(window=long_window).mean()
    data['EMA_5'] = data['Close'].ewm(span=short_window, adjust=False).mean()
    data['EMA_10'] = data['Close'].ewm(span=long_window, adjust=False).mean()
    return data


# 计算相对强弱指数
def calculate_rsi(data, window=14):
    delta = data['Close'].diff()
    gain = (delta.where(delta > 0, 0)).fillna(0)
    loss = (-delta.where(delta < 0, 0)).fillna(0)
    average_gain = gain.ewm(com=window - 1, min_periods=window).mean()
    average_loss = loss.ewm(com=window - 1, min_periods=window).mean()
    rs = average_gain / average_loss
    rsi = 100 - (100 / (1 + rs))
    return rsi


# 计算 MACD 和信号线
def calculate_macd(data):
    data['MACD'] = data['Close'].ewm(span=12, adjust=False).mean() - data['Close'].ewm(span=26, adjust=False).mean()
    data['Signal_Line'] = data['MACD'].ewm(span=9, adjust=False).mean()
    return data


# 处理数据
def process_data(file_path):
    # 加载数据
    data = pd.read_csv(file_path)

    # 计算移动平均线
    data = calculate_moving_averages(data)

    # 计算相对强弱指数
    data['RSI_14'] = calculate_rsi(data)

    # 计算 MACD 和信号线
    data = calculate_macd(data)

    return data


def add_future_high_low(data, future_periods=10):
    # 计算相对于当前开盘价的未来最高价和最低价
    # 通过用 NaN 替换 0 然后用下一个有效开盘价回填来避免除以零
    open_prices = data['Open'].replace(0, pd.NA).bfill()

    # 计算未来10分钟内的未来高点和低点
    future_highs = data['High'].rolling(window=future_periods, min_periods=1).max().shift(-future_periods)
    future_lows = data['Low'].rolling(window=future_periods, min_periods=1).min().shift(-future_periods)

    # 计算预期最高涨幅能否超过 5%
    data['Expected_Up5'] = ((future_highs - open_prices) / open_prices > 0.05).astype(int)
    data['Expected_Down5'] = ((future_lows - open_prices) / open_prices < -0.05).astype(int)

    # 填充可能由移位操作引起的任何剩余 NaN 值（在 DataFrame 的末尾）
    # data['Expected_Up5'].fillna(method='ffill', inplace=True)
    # data['Expected_Down5'].fillna(method='ffill', inplace=True)

    return data


# 处理单个文件时考虑时间间隙
def process_file_with_time_gaps(file_path):
    # 加载数据
    data = pd.read_csv(file_path)

    # 将“时间”列转换为日期时间
    data['Time'] = pd.to_datetime(data['Time'])

    # 按时间对数据进行排序，以防数据不按顺序排列
    data.sort_values('Time', inplace=True)

    # 初始化一个空的DataFrame来存储处理后的数据
    processed_data = pd.DataFrame()

    # 处理每段连续数据
    start_idx = 0
    for i in range(1, len(data)):
        # 检查时间间隔是否大于 1 分钟
        if (data['Time'].iloc[i] - data['Time'].iloc[i - 1]) > pd.Timedelta(minutes=1):
            # 处理连续段
            # 制作该段的显式副本以避免 SettingWithCopyWarning
            continuous_data = data.iloc[start_idx:i].copy()
            continuous_data = calculate_moving_averages(continuous_data)
            continuous_data['RSI_14'] = calculate_rsi(continuous_data)
            continuous_data = calculate_macd(continuous_data)
            continuous_data = add_future_high_low(continuous_data)

            # 将处理后的段附加到完整处理的数据中
            processed_data = pd.concat([processed_data, continuous_data], ignore_index=True)

            # 更新下一个段的起始索引
            start_idx = i

    # 处理最后一段
    # 制作该段的显式副本以避免 SettingWithCopyWarning
    final_segment = data.iloc[start_idx:].copy()
    final_segment = calculate_moving_averages(final_segment)
    final_segment['RSI_14'] = calculate_rsi(final_segment)
    final_segment = calculate_macd(final_segment)
    final_segment = add_future_high_low(final_segment)

    # 附加最终处理的段
    processed_data = pd.concat([processed_data, final_segment], ignore_index=True)

    return processed_data


# 处理给定目录中的所有 CSV 文件
def process_all_csv_in_directory(input_path, output_path):
    # 删除 output_path 目录中的所有文件
    for file in os.listdir(output_path):
        os.remove(os.path.join(output_path, file))
    # 遍历目录中的所有文件
    for file_name in os.listdir(input_path):
        # 检查文件是否为 CSV 文件
        if file_name.endswith('.csv'):
            file_path = os.path.join(input_path, file_name)

            # 处理每个文件
            try:
                data = process_file_with_time_gaps(file_path)

                # 将处理后的数据保存到新的 CSV 文件中
                save_path = os.path.join(output_path, f"processed_{file_name}")
                data.to_csv(save_path, index=False)
                print(f"Processed data saved to: {save_path}")
            except Exception as e:
                print(f"Failed to process file: {file_name}. Error: {e}")


input_path = '/training/Data/binanceData/high_frequency/collected'
output_path = '/training/Data/binanceData/high_frequency/processed'
process_all_csv_in_directory(input_path, output_path)
print("complete")

# 重新定义输入和输出目录
input_path = output_path
output_path = '/training/Data/binanceData/high_frequency/train'

# 确保输出目录存在
os.makedirs(output_path, exist_ok=True)

# 列出输入目录中的所有 CSV 文件
csv_files = glob(os.path.join(input_path, '*.csv'))

# 初始化一个空列表来保存数据帧
dfs = []

# 检查目录下是否有CSV文件
if not csv_files:
    print("No CSV files found in the directory.")

# 处理每个文件
for file_path in csv_files:
    try:
        # 加载数据
        data = pd.read_csv(file_path)

        # 删除具有任何 NaN 值的行并创建副本以避免 SettingWithCopyWarning
        data_cleaned = data.dropna().copy()

        # 将 Z-Score 标准化应用于除“时间”和未来价格列之外的所有列
        cols_to_normalize = data_cleaned.columns.difference(['Time', 'Expected_Up5', 'Expected_Down5'])
        data_cleaned.loc[:, cols_to_normalize] = data_cleaned.loc[:, cols_to_normalize].apply(zscore)

        # 将清理后的数据框附加到列表中
        dfs.append(data_cleaned)

    except Exception as e:
        print(f"An error occurred while processing {file_path}: {e}")

# 连接列表中的所有数据帧
if dfs:
    combined_df = pd.concat(dfs, ignore_index=True)
    # 定义组合文件的输出文件路径
    combined_file_path = os.path.join(output_path, 'combined_csv.csv')
    # 将组合数据框保存到单个 CSV 文件
    combined_df.to_csv(combined_file_path, index=False)
    print(f"All files have been combined and saved to: {combined_file_path}")
else:
    print("No dataframes to combine.")

# 加载数据
df = pd.read_csv("/training/Data/binanceData/high_frequency/train/combined_csv.csv")
# PyGWalker 分析 DataFrame：数据探索、创建图表和报告以及可视化交互
pyg.walk(df, hideDataSourceConfig=True, vegaTheme='g2')

# 显示数据框的前几行
df.head()

# 将时间列转换为日期时间
df['Time'] = pd.to_datetime(df['Time'])

# 以 YYYYMMDD 格式获取当前日期
today = datetime.datetime.now().strftime("%Y%m%d")
# 如果目录不存在，请创建该目录
model_directory = '/training/Models/CrazyTrades'
os.makedirs(model_directory, exist_ok=True)
# 使用日期后缀定义路径
model_save_path = os.path.join(model_directory, f'lstm_{today}.pth')


# 将数据帧拆分为数据帧列表的函数，其中每个数据帧都是连续的时间序列
def split_sequences(df, time_diff_threshold='2min'):
    """
    将 DataFrame 拆分为连续序列的列表。

    参数:
    - df: pd.DataFrame, 要分割的数据框
    - time_diff_threshold: str, 考虑序列中断的时间差阈值

    Returns:
    - list of pd.DataFrame, 其中每个数据帧是一个连续序列
    """
    sequences = []
    current_sequence = [df.iloc[0].to_dict()]  # 从第一行作为字典开始

    # 迭代数据框
    for _, row in df.iterrows():
        row = row.to_dict()  # 将行转换为字典
        # 如果时间差小于或等于阈值，则追加到当前序列
        if (row['Time'] - current_sequence[-1]['Time']) <= pd.Timedelta(time_diff_threshold):
            current_sequence.append(row)
        else:
            # 否则，开始一个新的序列
            sequences.append(pd.DataFrame(current_sequence))
            current_sequence = [row]
    sequences.append(pd.DataFrame(current_sequence))  # 添加最后一个序列

    return sequences


# 根据时间列拆分序列
sequences = split_sequences(df)

# 显示我们有多少个序列以及第一个序列的第一行
len(sequences), sequences[0].head()


# 使用相应标签创建序列滑动窗口的函数
def create_sliding_windows(sequences, input_window=15):
    X, y = [], []
    for sequence in sequences:
        # 删除训练时间列
        sequence = sequence.drop('Time', axis=1).values
        # 创建滑动窗口
        for i in range(len(sequence) - input_window):
            X.append(sequence[i:(i + input_window)])
            # 标签是未来10分钟预计的高点和低点涨幅
            # 由于标签已经预先计算，所以直接使用该行的Expected_High_Increase和Expected_Low_Increase
            y.append([
                sequence[i + input_window - 1, -2],  # Expected_Up5
                sequence[i + input_window - 1, -1]  # Expected_Down5
            ])
    return np.array(X), np.array(y)


# 为每个序列创建滑动窗口
# 现在 numpy 已导入，重新运行 create_sliding_windows 函数
X, y = create_sliding_windows(sequences)

# 将数据分为训练集和测试集
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

X_train.shape, y_train.shape, X_test.shape, y_test.shape

# 将设备设置为 GPU（如果可用）
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f'cuda: {torch.cuda.is_available()}')


# 定义 LSTM 模型
class LSTMModel(nn.Module):
    def __init__(self, input_size, hidden_layer_size, output_size):
        super().__init__()
        self.hidden_layer_size = hidden_layer_size

        self.lstm = nn.LSTM(input_size, hidden_layer_size)

        self.linear = nn.Linear(hidden_layer_size, output_size)

        self.hidden_cell = (torch.zeros(1, 1, self.hidden_layer_size).to(device),
                            torch.zeros(1, 1, self.hidden_layer_size).to(device))

    def forward(self, input_seq):
        lstm_out, self.hidden_cell = self.lstm(input_seq.view(len(input_seq), 1, -1), self.hidden_cell)
        predictions = self.linear(lstm_out.view(len(input_seq), -1))
        return predictions[-1]


# 实例化模型
input_size = X_train.shape[2]  # 特征数量
hidden_layer_size = 100
output_size = 2  # 预期最高涨幅和最低涨幅

model = LSTMModel(input_size, hidden_layer_size, output_size)
model = model.to(device)

# 显示模型架构
model

# 定义损失函数和优化器
loss_function = nn.MSELoss()
optimizer = torch.optim.Adam(model.parameters(), lr=0.001)


# 将数据转换为张量的函数
def create_inout_sequences(input_data, output_data):
    inout_seq = []
    for i in range(len(input_data)):
        train_seq = torch.FloatTensor(input_data[i]).to(device)
        train_label = torch.FloatTensor(output_data[i]).to(device)
        inout_seq.append((train_seq, train_label))
    return inout_seq


# 将训练数据转换为张量
train_inout_seq = create_inout_sequences(X_train, y_train)

# 训练和验证损失的记录
train_losses = []
test_losses = []
min_train_losses = 999
min_test_losses = 999

# 训练模型
epochs = 10

for i in range(epochs):
    # 将模型设置为训练模式
    model.train()
    train_loss = 0.0
    for seq, labels in train_inout_seq:
        optimizer.zero_grad()
        model.hidden_cell = (torch.zeros(1, 1, model.hidden_layer_size).to(device),
                             torch.zeros(1, 1, model.hidden_layer_size).to(device))

        y_pred = model(seq)

        loss = loss_function(y_pred, labels)
        loss.backward()
        optimizer.step()

        train_loss += loss.item()

    # 记录平均训练损失
    train_losses.append(train_loss / len(train_inout_seq))

    # 验证损失
    # 将模型设置为评估模式
    model.eval()
    test_loss = 0.0
    with torch.no_grad():
        for seq, labels in create_inout_sequences(X_test, y_test):
            y_test_pred = model(seq)
            t_loss = loss_function(y_test_pred, labels)
            test_loss += t_loss.item()

    # 记录平均测试损失
    test_losses.append(test_loss / len(X_test))

    print(f'Epoch {i} Training Loss: {train_losses[-1]:.8f} Test Loss: {test_losses[-1]:.8f}')
    if train_losses[-1] < min_train_losses and test_losses[-1] < min_test_losses:
        min_train_losses = train_losses[-1]
        min_test_losses = test_losses[-1]
        # 保存经过训练的模型
        torch.save(model.state_dict(), model_save_path)
        # 输出模型保存路径
        print(f"Model saved to {model_save_path}")

# 绘制训练和测试损失图
plt.figure(figsize=(12, 6))
# 训练损失
plt.plot(train_losses, label='Training Loss')
# 测试损失
plt.plot(test_losses, label='Test Loss')
plt.xlabel('Epochs')
plt.ylabel('Loss')
# 纪元内的训练和测试损失
plt.title('Training and Test Loss Over Epochs')
plt.legend()
plt.show()

# 将测试数据转换为张量
test_inputs = torch.FloatTensor(X_test).to(device)
test_labels = torch.FloatTensor(y_test).to(device)

# 重塑输入以匹配模型的预期输入
test_inputs = test_inputs.view(test_inputs.size(0), -1, input_size)

# 将模型设置为评估模式
model.eval()

# 评估不需要梯度
with torch.no_grad():
    # 初始化隐藏状态
    model.hidden_cell = (torch.zeros(1, 1, model.hidden_layer_size).to(device),
                         torch.zeros(1, 1, model.hidden_layer_size).to(device))

    # 迭代每个示例（为简单起见，假设批量大小为 1）
    predictions = []
    for i in range(test_inputs.size(0)):
        single_prediction = model(test_inputs[i])
        predictions.append(single_prediction)

    test_predictions = torch.stack(predictions)

# 计算测试数据的损失
test_loss = loss_function(test_predictions, test_labels)
print(f'Test Loss: {test_loss.item()}')

# 将预测和标签转换为 numpy 以进行绘图
test_predictions_np = test_predictions.numpy()
test_labels_np = test_labels.numpy()

# 绘制预测的高点增长和真实的高点增长
plt.figure(figsize=(14, 5))
plt.subplot(1, 2, 1)
# 预计最高涨幅超过阈值
plt.plot(test_predictions_np[:, 0], label='Predicted Can Over 5%')
# 真正的最高涨幅
plt.plot(test_labels_np[:, 0], label='True Can Over 5%')
# 最高涨幅的预测值与真实值比较
plt.title('Comparison of Predictions and True Values for High Increase')
plt.legend()

# 绘制预测最低涨幅和真实最低涨幅
plt.subplot(1, 2, 2)
# 预计最低涨幅
plt.plot(test_predictions_np[:, 1], label='Predicted Low Increase')
# 真正的最低涨幅
plt.plot(test_labels_np[:, 1], label='True Low Increase')
# 最低涨幅的预测值与真实值比较
plt.title('Comparison of Predictions and True Values for Low Increase')
plt.legend()

plt.show()
