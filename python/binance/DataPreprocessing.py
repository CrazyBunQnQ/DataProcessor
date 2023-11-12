import os
import pandas as pd
from scipy.stats import zscore
from glob import glob
import pygwalker as pyg


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

    # 计算预期最高和最低涨幅的百分比
    data['Expected_High_Increase'] = (future_highs - open_prices) / open_prices
    data['Expected_Low_Increase'] = (future_lows - open_prices) / open_prices

    # 填充可能由移位操作引起的任何剩余 NaN 值（在 DataFrame 的末尾）
    # data['Expected_High_Increase'].fillna(method='ffill', inplace=True)
    # data['Expected_Low_Increase'].fillna(method='ffill', inplace=True)

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
    # 遍历目录中的所有文件
    for file_name in os.listdir(input_path):
        # 检查文件是否为 CSV 文件
        if file_name.endswith('.csv'):
            file_path = os.path.join(input_path, file_name)

            # 处理每个文件
            try:
                print(f"Processing file: {file_name}")
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

# 定义输入和输出目录
input_directory = '/training/Data/binanceData/high_frequency/processed'
output_directory = '/training/Data/binanceData/high_frequency/train'

# 确保输出目录存在
os.makedirs(output_directory, exist_ok=True)

# 列出输入目录中的所有 CSV 文件
csv_files = glob(os.path.join(input_directory, '*.csv'))

# 初始化一个空列表来保存数据帧
dfs = []

# 检查目录下是否有CSV文件
if not csv_files:
    print("No CSV files found in the directory.")

# 处理每个文件
for file_path in csv_files:
    try:
        print(f"Processing file: {file_path}")
        # 加载数据
        data = pd.read_csv(file_path)

        # 删除具有任何 NaN 值的行并创建副本以避免 SettingWithCopyWarning
        data_cleaned = data.dropna().copy()

        # 将 Z-Score 标准化应用于除“时间”和未来价格列之外的所有列
        cols_to_normalize = data_cleaned.columns.difference(['Time', 'Expected_High_Increase', 'Expected_Low_Increase'])
        data_cleaned.loc[:, cols_to_normalize] = data_cleaned.loc[:, cols_to_normalize].apply(zscore)

        # 将清理后的数据框附加到列表中
        dfs.append(data_cleaned)
        print(f"File processed: {file_path}")

    except Exception as e:
        print(f"An error occurred while processing {file_path}: {e}")

# 连接列表中的所有数据帧
if dfs:
    combined_df = pd.concat(dfs, ignore_index=True)
    # 定义组合文件的输出文件路径
    combined_file_path = os.path.join(output_directory, 'combined_csv.csv')
    # 将组合数据框保存到单个 CSV 文件
    combined_df.to_csv(combined_file_path, index=False)
    print(f"All files have been combined and saved to: {combined_file_path}")
else:
    print("No dataframes to combine.")

# PyGWalker 分析 DataFrame：数据探索、创建图表和报告以及可视化交互
df = pd.read_csv("/training/Data/binanceData/high_frequency/train/combined_csv.csv")
pyg.walk(df, hideDataSourceConfig=True, vegaTheme='g2')
