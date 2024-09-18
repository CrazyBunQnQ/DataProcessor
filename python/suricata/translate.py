'''
Module for translating text using the LibreTranslate API.
'''
import hashlib
import json
import random
import re
import time
import urllib

import requests

translate_cache = {}

# Youdao
YOUDAO_URL = 'https://openapi.youdao.com/api'
APP_KEY = ''  # 请替换为您的有道应用ID
APP_SECRET = ''  # 请替换为您的有道应用密钥

# 提取翻译结果的正则表达式模式
pattern = r'["\']translatedText["\']: ["\']([^}]+)'

# 翻译过的内容
translated_text = set()
# 重复规则
repeat_rules = set()


def load_cache():
    global translate_cache
    try:
        # 如果本地文件存在则尝试读取上次保存的翻译缓存
        with open('translate_cache.json', 'r', encoding='utf-8') as f:
            translate_cache = json.load(f)
    except Exception as e:
        print('读取翻译缓存失败...')
        exit(1)


def save_cache():
    global translate_cache
    with open('translate_cache.json', 'w', encoding='utf-8') as f:
        json.dump(translate_cache, f, ensure_ascii=False, indent=4)


load_cache()
translate_count = 0


def send_push_notification(title, content, channel, token):
    """发送消息提醒"""
    url = "https://crazynft.top:3033/push/root"
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    data = {
        "title": title,
        "description": content,
        "content": content,
        "channel": channel,
        "token": token
    }
    response = requests.post(url, json=data, headers=headers)
    return response.status_code


def get_youdao_sign(query, app_key, app_secret):
    # 生成随机数和时间戳
    salt = str(int(time.time() * 1000) + random.randint(0, 10))
    sign_str = app_key + query + salt + app_secret
    sign = hashlib.md5(sign_str.encode('utf-8')).hexdigest()
    return salt, sign


def translate_by_youdao(text):
    global translate_count

    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }

    salt, sign = get_youdao_sign(text, APP_KEY, APP_SECRET)
    # urlencode
    text_encode = urllib.parse.quote(text)
    payload = {
        'q': text_encode,
        'from': 'en',
        'to': 'zh',
        'appKey': APP_KEY,
        'salt': salt,
        'sign': sign
    }
    # 将 payload 转换为 x-www-form-urlencoded 格式
    data = '&'.join([f'{key}={value}' for key, value in payload.items()])
    headers['Content-Length'] = str(len(data))

    while True:
        try:
            response = requests.post(YOUDAO_URL, headers=headers, data=data.encode('utf-8'), timeout=10)
            if response.status_code == 200:
                result = response.json()
                error_code = result.get('errorCode', 'Unknown error')
                if error_code == '411':
                    print("访问频率受限, 等待30秒再继续")
                    time.sleep(30)
                elif 'translation' in result:
                    translated_text = result['translation'][0]
                    translate_cache[text] = translated_text  # 存储翻译结果到缓存
                    translate_count += 1
                    save_cache()
                    print(f'Original: {text} —————— 翻译结果: {translated_text}')
                    time.sleep(1)
                    return translated_text
                else:
                    print(f"Error: {result.get('errorCode', 'Unknown error')}")
                    time.sleep(10)
            else:
                print(f"Error: {response.status_code}")
                time.sleep(10)
        except Exception as e:
            print(f"请求失败，将在 10 秒后重试... 错误: {str(e)}")
            time.sleep(10)


def translate_by_google(text, target_lang='zh'):
    global translate_count
    base_url = 'https://translate.googleapis.com/translate_a/single'

    # 通过URL编码文本内容
    text_encode = urllib.parse.quote(text)

    # 构建完整的翻译 URL
    params = {
        'client': 'gtx',  # 使用 gtx 客户端（网页接口）
        'sl': 'en',  # 源语言，自动检测
        'tl': target_lang,  # 目标语言
        'dt': 't',  # dt=t 表示请求翻译文本
        'q': text_encode  # 待翻译文本
    }

    url = f"{base_url}?client={params['client']}&sl={params['sl']}&tl={params['tl']}&dt={params['dt']}&q={params['q']}"

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0"
    }

    while True:
        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                result = response.json()
                if result:
                    # 获取翻译结果
                    translated_text = ''.join([item[0] for item in result[0]])
                    translate_cache[text] = translated_text  # 存储翻译结果到缓存
                    translate_count += 1
                    save_cache()  # 保存缓存
                    print(f'Original: {text} —————— 翻译结果: {translated_text}')
                    time.sleep(1)
                    return translated_text
                else:
                    print(f"翻译失败，未获得翻译结果。")
                    time.sleep(10)
            else:
                print(f"Error: {response.status_code}")
                time.sleep(10)
        except Exception as e:
            print(f"请求失败，将在 10 秒后重试... 错误: {str(e)}")
            time.sleep(10)


def translate_text(text, retry=True):
    global translate_count
    global translate_cache
    # if text in translated_text:
    # repeat_rules.add(text)
    # print("\n  注意以下规则有重复:")
    # for translated in repeat_rules:
    #     print(translated)
    # print("end\n")
    translated_text.add(text)
    # 检查缓存
    if text in translate_cache:
        return translate_cache[text]
    # return translate_by_openai(text, retry)
    # return translate_by_youdao(text)
    return translate_by_google(text)
