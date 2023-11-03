import csv
from datetime import datetime, timedelta
from binance.client import Client
from binance.exceptions import BinanceAPIException

# Binance API 密钥
api_key = 'YOUR_API_KEY'
api_secret = 'YOUR_API_SECRET'

# 创建 Binance 客户端实例
client = Client(api_key, api_secret)

def get_top_volume_pairs():
    """ 获取前一天所有交易对的交易量数据并选取前 25 """
    yesterday = datetime.utcnow() - timedelta(days=1)
    start_str = yesterday.strftime('%Y-%m-%d 00:00:00')
    end_str = yesterday.strftime('%Y-%m-%d 23:59:59')

    tickers = client.get_ticker()

    # 筛选出交易量，并排序
    volumes = [
        (ticker['symbol'], float(ticker['quoteVolume']))
        for ticker in tickers if ticker['symbol'].endswith('USDT')
    ]
    volumes.sort(key=lambda x: x[1], reverse=True)

    # 返回前 25 个交易对
    return volumes[:25]

def get_hourly_volume_data_for_pair(symbol, threshold_volume, threshold_amplitude):
    """ 获取前一天每个小时的交易量数据 """
    yesterday = datetime.utcnow() - timedelta(days=1)
    start_str = yesterday.strftime('%Y-%m-%d 00:00:00')
    end_str = yesterday.strftime('%Y-%m-%d 23:59:59')

    klines = client.get_historical_klines(symbol, Client.KLINE_INTERVAL_1HOUR, start_str, end_str)

    significant_times = []
    for kline in klines:
        open_time = datetime.fromtimestamp(kline[0] / 1000)
        volume = float(kline[5])
        high_price = float(kline[2])
        low_price = float(kline[3])
        amplitude = (high_price - low_price) / low_price

        if volume >= threshold_volume and amplitude >= threshold_amplitude:
            significant_times.append(open_time.strftime('%Y-%m-%d %H:%M:%S'))

    return significant_times

def save_minute_data_to_csv(symbol, start_time):
    """ 保存特定时段的分钟级别数据到 CSV 文件 """
    end_time = start_time + timedelta(hours=1)

    klines = client.get_historical_klines(symbol, Client.KLINE_INTERVAL_1MINUTE, start_time.strftime('%Y-%m-%d %H:%M:%S'), end_time.strftime('%Y-%m-%d %H:%M:%S'))

    with open(f'{symbol}_minute_data.csv', 'w', newline='') as csvfile:
        fieldnames = ['open_time', 'open', 'high', 'low', 'close', 'volume']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        for kline in klines:
            writer.writerow({
                'open_time': datetime.fromtimestamp(kline[0] / 1000).strftime('%Y-%m-%d %H:%M:%S'),
                'open': kline[1],
                'high': kline[2],
                'low': kline[3],
                'close': kline[4],
                'volume': kline[5],
            })

# 主执行流程
if __name__ == "__main__":
    try:
        top_pairs = get_top_volume_pairs()
        for symbol, volume in top_pairs:
            print(f'Checking {symbol}...')
            significant_times = get_hourly_volume_data_for_pair(symbol, threshold_volume=100000, threshold_amplitude=0.01)  # 阈值需根据实际情况设置
            for time in significant_times:
                time = datetime.strptime(time, '%Y-%m-%d %H:%M:%S')
                save_minute_data_to_csv(symbol, time)
                print(f'Saved minute data for {symbol} at {time}.')

        print('All done!')

    except BinanceAPIException as e:
        print(f"An exception occurred: {e}")
