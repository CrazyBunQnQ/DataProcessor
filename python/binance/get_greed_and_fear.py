import requests

def get_fear_and_greed_index():
    url = "https://alternative.me/api/crypto/fear-and-greed-index/history"
    response = requests.post(url)
    if response.status_code == 200:
        data = response.json()
        values = data["data"]["datasets"][0]["data"]
        # 获取最后一个值
        yesterday_index = values[-1]
        return yesterday_index
    else:
        print("请求失败")

index = get_fear_and_greed_index()
print("前一天的恐慌与贪婪值为:", index)
