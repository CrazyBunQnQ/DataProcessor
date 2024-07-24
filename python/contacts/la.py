import os
import random
import time

import requests

base_url = "https://192.168.0.239:9002"
m3_cookie = 'JSESSIONID=C510D7499F4CA4130272'
save_file = 'contacts.csv'
saved_contacts = set()
saved_deps = set()


# 以 utf-8 写入文件

def fetch_departments():
    url = f'{base_url}/seeyon/rest/contacts2/get/departments/670869647114347/0/1000'
    headers = {
        'Cookie': m3_cookie,
        'User-Agent': 'seeyon-m3/4.3.9',
        # 10位时间戳
        'sendtime': str(int(time.time()))
    }
    params = {
        'cmprnd': str(random.randint(10000000, 99999999))
    }

    try:
        response = requests.get(url, headers=headers, params=params, verify=False)
        if response.status_code == 200:
            data = response.json()
            departments = data['data']['departments']
            return departments
        else:
            print(f"Request failed with status code {response.status_code}")
            return None
    except requests.RequestException as e:
        print(f"Request failed: {e}")
        return None


def fetch_child_departments_and_members(department_id):
    url = f'{base_url}/seeyon/rest/contacts2/department/children/{department_id}/1/100/department'
    headers = {
        'Cookie': m3_cookie,
        'User-Agent': 'seeyon-m3/4.3.9',
        # 10位时间戳
        'sendtime': str(int(time.time()))
    }
    params = {
        'cmprnd': str(random.randint(10000000, 99999999))
    }

    try:
        response = requests.get(url, headers=headers, params=params, verify=False)
        if response.status_code == 200:
            data = response.json()
            departments = data['data']['childrenDepartments']
            members = data['data']['members']
            return departments, members
        else:
            print(f"Request failed with status code {response.status_code}")
            return None, None
    except requests.RequestException as e:
        print(f"Request failed: {e}")
        return None, None


def save_contacts(department_id):
    if department_id in saved_deps:
        print(f'Department {department_id} has been saved.')
        return
    saved_deps.add(department_id)
    child_departments, members = fetch_child_departments_and_members(department_id)
    if members:
        for member in members:
            contact = f'{member["name"]},{member["postName"]},{member["tel"]},{member["id"]}'
            if contact not in saved_contacts:
                saved_contacts.add(contact)
                with open(save_file, 'a', encoding='utf-8') as f:
                    f.write(contact + '\n')
    if child_departments:
        for child_department in child_departments:
            print(f'Saving contacts for department {child_department["name"]}')
            save_contacts(child_department['id'])


# Example usage:
if os.path.exists(save_file):
    os.remove(save_file)
departments_list = fetch_departments()

if departments_list:
    print("Departments:")
    for department in departments_list:
        save_contacts(department['id'])
else:
    print("Failed to fetch departments.")
