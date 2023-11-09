import pandas as pd

# 加载数据
file_path = '/training/Data/binanceData/high_frequency/train/combined_csv.csv'
data = pd.read_csv(file_path)

# 显示数据框的前几行
data.head()

from datetime import datetime, timedelta

# 将时间列转换为日期时间
data['Time'] = pd.to_datetime(data['Time'])


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
sequences = split_sequences(data)

# 显示我们有多少个序列以及第一个序列的第一行
len(sequences), sequences[0].head()

from sklearn.model_selection import train_test_split
import numpy as np


# 使用相应标签创建序列滑动窗口的函数
def create_sliding_windows(sequences, input_window=15, output_window=10):
    X, y = [], []
    for sequence in sequences:
        # 删除训练时间列
        sequence = sequence.drop('Time', axis=1).values
        # 创建滑动窗口
        for i in range(len(sequence) - input_window - output_window):
            X.append(sequence[i:(i + input_window)])
            # 标签是未来10分钟预计的高点和低点涨幅
            future_slice = sequence[(i + input_window):(i + input_window + output_window)]
            y.append([
                future_slice[:, -2].max(),  # Expected_High_Increase
                future_slice[:, -1].min()  # Expected_Low_Increase
            ])
    return np.array(X), np.array(y)


# 为每个序列创建滑动窗口
# 现在 numpy 已导入，重新运行 create_sliding_windows 函数
X, y = create_sliding_windows(sequences)

# 将数据分为训练集和测试集
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

X_train.shape, y_train.shape, X_test.shape, y_test.shape

import torch
import torch.nn as nn

# 将设备设置为 GPU（如果可用）
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")


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

    print(f'Epoch {i} Training Loss: {train_losses[-1]:.6f} Test Loss: {test_losses[-1]:.6f}')

import matplotlib.pyplot as plt

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

import matplotlib.pyplot as plt

# 将预测和标签转换为 numpy 以进行绘图
test_predictions_np = test_predictions.numpy()
test_labels_np = test_labels.numpy()

# 绘制预测的高点增长和真实的高点增长
plt.figure(figsize=(14, 5))
plt.subplot(1, 2, 1)
# 预计最高涨幅
plt.plot(test_predictions_np[:, 0], label='Predicted High Increase')
# 真正的最高涨幅
plt.plot(test_labels_np[:, 0], label='True High Increase')
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


# 保存模型
import datetime
import os

# 以 YYYYMMDD 格式获取当前日期
today = datetime.datetime.now().strftime("%Y%m%d")

# 如果目录不存在，请创建该目录
model_directory = '/training/Models/CrazyTrades'
os.makedirs(model_directory, exist_ok=True)

# 使用日期后缀定义路径
model_save_path = os.path.join(model_directory, f'lstm_{today}.pth')
# 保存经过训练的模型
torch.save(model.state_dict(), model_save_path)

# 输出模型保存路径
print(f"Model saved to {model_save_path}")

