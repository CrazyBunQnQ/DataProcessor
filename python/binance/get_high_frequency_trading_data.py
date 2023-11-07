import csv
from datetime import datetime, timedelta
from binance.client import Client
from binance.exceptions import BinanceAPIException
import os

# Binance API 密钥
api_key = 'YOUR_API_KEY'
api_secret = 'YOUR_API_SECRET'

# 创建 Binance 客户端实例
client = Client(api_key, api_secret)

# 设置阈值
THRESHOLD_VOLUME = 30000000
THRESHOLD_AMPLITUDE = 0.03

def get_historical_funding_rates(symbol, limit=500):
    """
    获取指定交易对的历史资金费率。

    :param symbol: 交易对，例如 'BTCUSDT'
    :param limit: 获取记录的数量，默认为500，最大可为1000
    :return: 资金费率的历史记录
    """
    funding_rates = client.futures_funding_rate(symbol=symbol, limit=limit)
    return funding_rates

def get_open_futures_positions(symbol):
    # 获取未平仓的期货合约
    position_info = client.futures_position_information(symbol=symbol)
    return position_info

def get_previous_day_tickers():
    tickers = client.get_ticker()
    usdt_pairs = [ticker for ticker in tickers if ticker['symbol'].endswith('USDT')]
    sorted_pairs = sorted(usdt_pairs, key=lambda x: float(x['quoteVolume']), reverse=True)
    top_pairs = sorted_pairs[:25]
    return [pair['symbol'] for pair in top_pairs]

def fetch_trades(symbol, start_str, end_str):
    trades = client.get_historical_klines(symbol, Client.KLINE_INTERVAL_1MINUTE, start_str, end_str)
    return trades

def check_existing_data(file_name, last_data):
    try:
        with open(file_name, 'r') as file:
            for line in reversed(list(csv.reader(file))):
                if line[0] == last_data:
                    return True
        return False
    except FileNotFoundError:
        return False

def save_to_csv(symbol, trades, date_str):
    # file_name = f"/training/Data/binanceData/high_frequency/{symbol}_{date_str}.csv"
    file_name = f"{symbol}_{date_str}.csv"
    last_data_time = None

    # 检查文件是否存在并找到最后一条数据的时间
    if os.path.exists(file_name):
        with open(file_name, 'r') as file:
            csv_reader = csv.reader(file)
            last_row = None
            for last_row in csv_reader:
                pass
            if last_row:
                last_data_time = last_row[0]

    with open(file_name, mode='a', newline='') as file:
        writer = csv.writer(file)
        # 如果是文件的开始，则写入标题
        if file.tell() == 0:
            # columns=['timestamp', 'open', 'high', 'low', 'close', 'volume', 'close_time', 'quote_asset_volume', 'number_of_trades', 'taker_buy_base_asset_volume', 'taker_buy_quote_asset_volume', 'ignore'])
            writer.writerow(['Time', 'Open', 'High', 'Low', 'Close', 'Volume', 'NumberOfTrades'])
        # 写入数据
        for trade in trades:
            trade_time = datetime.fromtimestamp(trade[0] / 1000).strftime('%Y-%m-%d %H:%M:%S')
            # 如果数据时间大于上次保存的最后时间，则保存数据
            if not last_data_time or trade_time > last_data_time:
                writer.writerow([trade_time, trade[1], trade[2], trade[3], trade[4], trade[5], trade[8]])


def process_data(symbol, trades, date_str):
    continuous_hours = []
    saved = False
    for i in range(0, len(trades) - 59):
        hour_volume = sum(float(trade[5]) for trade in trades[i:i+60])
        hour_high = max(float(trade[2]) for trade in trades[i:i+60])
        hour_low = min(float(trade[3]) for trade in trades[i:i+60])
        hour_open = float(trades[i][1])
        hour_close = float(trades[i+59][4])

        amplitude = (hour_high - hour_low) / hour_open

        if hour_volume >= THRESHOLD_VOLUME and amplitude >= THRESHOLD_AMPLITUDE:
            continuous_hours.append(trades[i:i+60])
        if continuous_hours:
            saved = True
            # 如果连续小时结束，保存并重置列表
            all_trades = [item for sublist in continuous_hours for item in sublist]
            save_to_csv(symbol, all_trades, date_str)
            continuous_hours = []

    if saved:
        print(f'Saved minute data for {symbol}.')

# 主执行流程
if __name__ == "__main__":
    previous_day = datetime.utcnow() - timedelta(days=1)
    date_str = previous_day.strftime('%Y%m%d')
    start_str = previous_day.strftime('%d %b, %Y 00:00:00')
    end_str = (previous_day + timedelta(days=1)).strftime('%d %b, %Y 00:00:00')

    top_symbols = get_previous_day_tickers()

    for symbol in top_symbols:
        print(f'Checking {symbol}...')
        try:
            trades = fetch_trades(symbol, start_str, end_str)
            process_data(symbol, trades, date_str)
        except BinanceAPIException as e:
            print(f"API Exception for {symbol}: {e}")
    print("finish")
