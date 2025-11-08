# -*- coding: utf-8 -*-
"""
iVasms -> Telegram Bot (Playwright + httpx)
Full code including COMPLETE COUNTRY_FLAGS, SERVICE_KEYWORDS, SERVICE_EMOJIS
Replace YOUR_BOT_TOKEN, ADMIN_CHAT_IDS, USERNAME, PASSWORD before running.
"""

import asyncio
import json
import os
import re
import time
import traceback
from datetime import datetime, timedelta
from urllib.parse import urljoin

import httpx
import subprocess
import sys
import os
from colorama import Fore, Style

def ensure_playwright_browsers():
    # jika kamu ingin menghindari install berulang, buat flag file sederhana
    flag_path = ".playwright_installed"
    # Railway/re-deploy bisa menghapus file ini — tapi tetap aman
    if os.path.exists(flag_path):
        return
    try:
        print(Fore.CYAN + "[playwright] Installing browsers (chromium)..." + Style.RESET_ALL)
        cmd = [sys.executable, "-m", "playwright", "install", "chromium"]
        completed = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=600)
        print(Fore.GREEN + "[playwright] Install completed." + Style.RESET_ALL)
        # tulis flag agar tidak mengulang (opsional)
        with open(flag_path, "w") as f:
            f.write("ok")
    except subprocess.CalledProcessError as e:
        print(Fore.RED + "[playwright] Install failed:" + Style.RESET_ALL)
        print(e.stdout)
        print(e.stderr)
    except Exception as e:
        print(Fore.RED + f"[playwright] Install error: {e}" + Style.RESET_ALL)

# Pastikan ini dijalankan sebelum import/use Playwright
ensure_playwright_browsers()
from bs4 import BeautifulSoup
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes

from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError

# ----------------- CONFIG -----------------
YOUR_BOT_TOKEN = "7770869052:AAGofeXJ-wtle3HCRCmGV7-GauvuePuBOTM"  # <-- replace
ADMIN_CHAT_IDS = ["6246550447"]  # <-- replace with your admin user IDs (strings)
INITIAL_CHAT_IDS = ["-1002249225519"]

LOGIN_URL = "https://www.ivasms.com/login"
BASE_URL = "https://www.ivasms.com/"
SMS_API_ENDPOINT = "https://www.ivasms.com/portal/sms/received/getsms"

USERNAME = "emailsayabang@gmail.com"  # <-- replace
PASSWORD = "dnR#9LNvGJAVNjr"           # <-- replace

POLLING_INTERVAL_SECONDS = 5
STATE_FILE = "processed_sms_ids.json"
CHAT_IDS_FILE = "chat_ids.json"
COOKIES_FILE = "cookies_playwright.json"
COOKIES_TTL_SECONDS = 60 * 30  # 30 minutes

# ----------------- COUNTRY FLAGS (complete list) -----------------
COUNTRY_FLAGS = {
    "Afghanistan": "🇦🇫", "Albania": "🇦🇱", "Algeria": "🇩🇿", "Andorra": "🇦🇩", "Angola": "🇦🇴",
    "Argentina": "🇦🇷", "Armenia": "🇦🇲", "Australia": "🇦🇺", "Austria": "🇦🇹", "Azerbaijan": "🇦🇿",
    "Bahrain": "🇧🇭", "Bangladesh": "🇧🇩", "Belarus": "🇧🇾", "Belgium": "🇧🇪", "Benin": "🇧🇯",
    "Bhutan": "🇧🇹", "Bolivia": "🇧🇴", "Brazil": "🇧🇷", "Bulgaria": "🇧🇬", "Burkina Faso": "🇧🇫",
    "Cambodia": "🇰🇭", "Cameroon": "🇨🇲", "Canada": "🇨🇦", "Chad": "🇹🇩", "Chile": "🇨🇱",
    "China": "🇨🇳", "Colombia": "🇨🇴", "Congo": "🇨🇬", "Croatia": "🇭🇷", "Cuba": "🇨🇺",
    "Cyprus": "🇨🇾", "Czech Republic": "🇨🇿", "Denmark": "🇩🇰", "Egypt": "🇪🇬", "Estonia": "🇪🇪",
    "Ethiopia": "🇪🇹", "Finland": "🇫🇮", "France": "🇫🇷", "Gabon": "🇬🇦", "Gambia": "🇬🇲",
    "Georgia": "🇬🇪", "Germany": "🇩🇪", "Ghana": "🇬🇭", "Greece": "🇬🇷", "Guatemala": "🇬🇹",
    "Guinea": "🇬🇳", "Haiti": "🇭🇹", "Honduras": "🇭🇳", "Hong Kong": "🇭🇰", "Hungary": "🇭🇺",
    "Iceland": "🇮🇸", "India": "🇮🇳", "Indonesia": "🇮🇩", "Iran": "🇮🇷", "Iraq": "🇮🇶",
    "Ireland": "🇮🇪", "Israel": "🇮🇱", "Italy": "🇮🇹", "IVORY COAST": "🇨🇮", "Ivory Coast": "🇨🇮", "Jamaica": "🇯🇲",
    "Japan": "🇯🇵", "Jordan": "🇯🇴", "Kazakhstan": "🇰🇿", "Kenya": "🇰🇪", "Kuwait": "🇰🇼",
    "Kyrgyzstan": "🇰🇬", "Laos": "🇱🇦", "Latvia": "🇱🇻", "Lebanon": "🇱🇧", "Liberia": "🇱🇷",
    "Libya": "🇱🇾", "Lithuania": "🇱🇹", "Luxembourg": "🇱🇺", "Madagascar": "🇲🇬", "Malaysia": "🇲🇾",
    "Mali": "🇲🇱", "Malta": "🇲🇹", "Mexico": "🇲🇽", "Moldova": "🇲🇩", "Monaco": "🇲🇨",
    "Mongolia": "🇲🇳", "Montenegro": "🇲🇪", "Morocco": "🇲🇦", "Mozambique": "🇲🇿", "Myanmar": "🇲🇲",
    "Namibia": "🇳🇦", "Nepal": "🇳🇵", "Netherlands": "🇳🇱", "New Zealand": "🇳🇿", "Nicaragua": "🇳🇮",
    "Niger": "🇳🇪", "Nigeria": "🇳🇬", "North Korea": "🇰🇵", "North Macedonia": "🇲🇰", "Norway": "🇳🇴",
    "Oman": "🇴🇲", "Pakistan": "🇵🇰", "Panama": "🇵🇦", "Paraguay": "🇵🇾", "Peru": "🇵🇪",
    "Philippines": "🇵🇭", "Poland": "🇵🇱", "Portugal": "🇵🇹", "Qatar": "🇶🇦", "Romania": "🇷🇴",
    "Russia": "🇷🇺", "Rwanda": "🇷🇼", "Saudi Arabia": "🇸🇦", "Senegal": "🇸🇳", "Serbia": "🇷🇸",
    "Sierra Leone": "🇸🇱", "Singapore": "🇸🇬", "Slovakia": "🇸🇰", "Slovenia": "🇸🇮", "Somalia": "🇸🇴",
    "South Africa": "🇿🇦", "South Korea": "🇰🇷", "Spain": "🇪🇸", "Sri Lanka": "🇱🇰", "Sudan": "🇸🇩",
    "Sweden": "🇸🇪", "Switzerland": "🇨🇭", "Syria": "🇸🇾", "Taiwan": "🇹🇼", "Tajikistan": "🇹🇯",
    "Tanzania": "🇹🇿", "Thailand": "🇹🇭", "TOGO": "🇹🇬", "Tunisia": "🇹🇳", "Turkey": "🇹🇷",
    "Turkmenistan": "🇹🇲", "Uganda": "🇺🇬", "Ukraine": "🇺🇦", "United Arab Emirates": "🇦🇪", "United Kingdom": "🇬🇧",
    "United States": "🇺🇸", "Uruguay": "🇺🇾", "Uzbekistan": "🇺🇿", "Venezuela": "🇻🇪", "Vietnam": "🇻🇳",
    "Yemen": "🇾🇪", "Zambia": "🇿🇲", "Zimbabwe": "🇿🇼", "Unknown Country": "🏴‍☠️"
}

# ----------------- SERVICE KEYWORDS (complete-ish list) -----------------
SERVICE_KEYWORDS = {
    "Facebook": ["facebook"],
    "Google": ["google", "gmail"],
    "WhatsApp": ["whatsapp"],
    "Telegram": ["telegram"],
    "Instagram": ["instagram"],
    "Amazon": ["amazon"],
    "Netflix": ["netflix"],
    "LinkedIn": ["linkedin"],
    "Microsoft": ["microsoft", "outlook", "live.com"],
    "Apple": ["apple", "icloud"],
    "Twitter": ["twitter"],
    "Snapchat": ["snapchat"],
    "TikTok": ["tiktok"],
    "Discord": ["discord"],
    "Signal": ["signal"],
    "Viber": ["viber"],
    "IMO": ["imo"],
    "PayPal": ["paypal"],
    "Binance": ["binance"],
    "Uber": ["uber"],
    "Bolt": ["bolt"],
    "Airbnb": ["airbnb"],
    "Yahoo": ["yahoo"],
    "Steam": ["steam"],
    "Blizzard": ["blizzard"],
    "Foodpanda": ["foodpanda"],
    "Pathao": ["pathao"],
    "Messenger": ["messenger", "meta"],
    "Gmail": ["gmail", "google"],
    "YouTube": ["youtube", "google"],
    "X": [" x ", "twitter"],  # space-surrounded x to reduce false positives
    "eBay": ["ebay"],
    "AliExpress": ["aliexpress"],
    "Alibaba": ["alibaba"],
    "Flipkart": ["flipkart"],
    "Outlook": ["outlook", "microsoft"],
    "Skype": ["skype", "microsoft"],
    "Spotify": ["spotify"],
    "iCloud": ["icloud", "apple"],
    "Stripe": ["stripe"],
    "Cash App": ["cash app", "square cash"],
    "Venmo": ["venmo"],
    "Zelle": ["zelle"],
    "Wise": ["wise", "transferwise"],
    "Coinbase": ["coinbase"],
    "KuCoin": ["kucoin"],
    "Bybit": ["bybit"],
    "OKX": ["okx"],
    "Huobi": ["huobi"],
    "Kraken": ["kraken"],
    "MetaMask": ["metamask"],
    "Epic Games": ["epic games", "epicgames"],
    "PlayStation": ["playstation", "psn"],
    "Xbox": ["xbox", "microsoft"],
    "Twitch": ["twitch"],
    "Reddit": ["reddit"],
    "ProtonMail": ["protonmail", "proton"],
    "Zoho": ["zoho"],
    "Quora": ["quora"],
    "StackOverflow": ["stackoverflow"],
    "Indeed": ["indeed"],
    "Upwork": ["upwork"],
    "Fiverr": ["fiverr"],
    "Glassdoor": ["glassdoor"],
    "Booking.com": ["booking.com", "booking"],
    "Careem": ["careem"],
    "Swiggy": ["swiggy"],
    "Zomato": ["zomato"],
    "McDonald's": ["mcdonalds", "mcdonald's"],
    "KFC": ["kfc"],
    "Nike": ["nike"],
    "Adidas": ["adidas"],
    "Shein": ["shein"],
    "OnlyFans": ["onlyfans"],
    "Tinder": ["tinder"],
    "Bumble": ["bumble"],
    "Grindr": ["grindr"],
    "Line": ["line"],
    "WeChat": ["wechat"],
    "VK": ["vk", "vkontakte"],
    "Unknown": ["unknown"]
}

# ----------------- SERVICE EMOJIS (complete-ish mapping) -----------------
SERVICE_EMOJIS = {
    "Telegram": "📩", "WhatsApp": "🟢", "Facebook": "📘", "Instagram": "📸", "Messenger": "💬",
    "Google": "🔍", "Gmail": "✉️", "YouTube": "▶️", "Twitter": "🐦", "X": "❌",
    "TikTok": "🎵", "Snapchat": "👻", "Amazon": "🛒", "eBay": "📦", "AliExpress": "📦",
    "Alibaba": "🏭", "Flipkart": "📦", "Microsoft": "🪟", "Outlook": "📧", "Skype": "📞",
    "Netflix": "🎬", "Spotify": "🎶", "Apple": "🍏", "iCloud": "☁️", "PayPal": "💰",
    "Stripe": "💳", "Cash App": "💵", "Venmo": "💸", "Zelle": "🏦", "Wise": "🌐",
    "Binance": "🪙", "Coinbase": "🪙", "KuCoin": "🪙", "Bybit": "📈", "OKX": "🟠",
    "Huobi": "🔥", "Kraken": "🐙", "MetaMask": "🦊", "Discord": "🗨️", "Steam": "🎮",
    "Epic Games": "🕹️", "PlayStation": "🎮", "Xbox": "🎮", "Twitch": "📺", "Reddit": "👽",
    "Yahoo": "🟣", "ProtonMail": "🔐", "Zoho": "📬", "Quora": "❓", "StackOverflow": "🧑‍💻",
    "LinkedIn": "💼", "Indeed": "📋", "Upwork": "🧑‍💻", "Fiverr": "💻", "Glassdoor": "🔎",
    "Airbnb": "🏠", "Booking.com": "🛏️", "Uber": "🚗", "Lyft": "🚕", "Bolt": "🚖",
    "Careem": "🚗", "Swiggy": "🍔", "Zomato": "🍽️", "Foodpanda": "🍱",
    "McDonald's": "🍟", "KFC": "🍗", "Nike": "👟", "Adidas": "👟", "Shein": "👗",
    "OnlyFans": "🔞", "Tinder": "🔥", "Bumble": "🐝", "Grindr": "😈", "Signal": "🔐",
    "Viber": "📞", "Line": "💬", "WeChat": "💬", "VK": "🌐", "Unknown": "❓"
}

# ----------------- Chat ID management -----------------
def load_chat_ids():
    if not os.path.exists(CHAT_IDS_FILE):
        with open(CHAT_IDS_FILE, "w") as f:
            json.dump(INITIAL_CHAT_IDS, f)
        return INITIAL_CHAT_IDS.copy()
    try:
        with open(CHAT_IDS_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return INITIAL_CHAT_IDS.copy()

def save_chat_ids(chat_ids):
    with open(CHAT_IDS_FILE, "w") as f:
        json.dump(chat_ids, f, indent=2)

# ----------------- Processed IDs -----------------
def load_processed_ids():
    if not os.path.exists(STATE_FILE): return set()
    try:
        with open(STATE_FILE, "r") as f:
            return set(json.load(f))
    except Exception:
        return set()

def save_processed_id(sms_id):
    processed = load_processed_ids()
    processed.add(sms_id)
    with open(STATE_FILE, "w") as f:
        json.dump(list(processed), f)

# ----------------- Playwright login -----------------
async def playwright_login_and_extract(username: str, password: str, headless: bool = True, wait_for_dashboard_selector: str = "meta[name='csrf-token']"):
    print("🔵 Playwright: launching browser to perform login...")
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=headless)
        context = await browser.new_context()
        page = await context.new_page()
        try:
            await page.goto(LOGIN_URL, wait_until="load", timeout=60000)
            # Fill form fields
            try:
                await page.fill("input[name=email]", username, timeout=5000)
            except Exception:
                try:
                    await page.fill("input[type=email]", username, timeout=3000)
                except Exception:
                    pass
            try:
                await page.fill("input[name=password]", password, timeout=5000)
            except Exception:
                try:
                    await page.fill("input[type=password]", password, timeout=3000)
                except Exception:
                    pass

            # Try clicking submit
            submit_clicked = False
            for sel in ["button[type=submit]", "button:has-text('Login')", "button:has-text('Sign In')", "input[type=submit]"]:
                try:
                    await page.click(sel, timeout=3000)
                    submit_clicked = True
                    break
                except Exception:
                    continue
            if not submit_clicked:
                try:
                    await page.press("input[name=password]", "Enter")
                except Exception:
                    pass

            # Wait for CSRF meta or network idle
            try:
                await page.wait_for_selector(wait_for_dashboard_selector, timeout=20000)
            except PlaywrightTimeoutError:
                try:
                    await page.wait_for_load_state("networkidle", timeout=20000)
                except Exception:
                    pass

            page_html = await page.content()
            cookies = await context.cookies()
            soup = BeautifulSoup(page_html, "html.parser")
            csrf_meta = soup.find("meta", {"name": "csrf-token"})
            csrf_token = csrf_meta.get("content") if csrf_meta else None

            await browser.close()
            print("✅ Playwright login finished.")
            return cookies, csrf_token, page_html

        except Exception as e:
            try:
                # ambil screenshot & HTML untuk debugging (simpan di file)
                html = await page.content()
                with open("playwright_error_page.html", "w", encoding="utf-8") as fh:
                    fh.write(html)
                await page.screenshot(path="playwright_error_screenshot.png")
                print("✅ Saved playwright_error_page.html and playwright_error_screenshot.png for debugging.")
            except Exception:
                pass

            await browser.close()
            print("❌ Playwright login error:", e)
            traceback.print_exc()
            return [], None, ""

# ----------------- Cookie utils -----------------
def cookies_list_to_cookie_header(cookies_list):
    return "; ".join(f"{c['name']}={c['value']}" for c in cookies_list)

def save_cookies_file(cookies_list, csrf_token=None):
    payload = {"cookies": cookies_list, "csrf_token": csrf_token, "saved_at": time.time()}
    with open(COOKIES_FILE, "w") as f:
        json.dump(payload, f, indent=2)

def load_cookies_file():
    if not os.path.exists(COOKIES_FILE): return None
    try:
        with open(COOKIES_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return None

def cookies_expired(cookies_payload):
    if not cookies_payload: return True
    saved_at = cookies_payload.get("saved_at", 0)
    return (time.time() - saved_at) > COOKIES_TTL_SECONDS

# ----------------- Fetch SMS via httpx -----------------
async def fetch_sms_from_api_with_cookies(client: httpx.AsyncClient, headers: dict, csrf_token: str):
    all_messages = []
    try:
        today = datetime.utcnow()
        start_date = today - timedelta(days=1)
        from_date_str, to_date_str = start_date.strftime("%m/%d/%Y"), today.strftime("%m/%d/%Y")
        first_payload = {"from": from_date_str, "to": to_date_str, "_token": csrf_token}
        summary_response = await client.post(SMS_API_ENDPOINT, headers=headers, data=first_payload, timeout=30.0)
        summary_response.raise_for_status()
        summary_soup = BeautifulSoup(summary_response.text, "html.parser")
        group_divs = summary_soup.find_all("div", {"class": "pointer"})
        if not group_divs:
            return []

        group_ids = []
        for div in group_divs:
            onclick = div.get("onclick", "")
            m = re.search(r"getDetials\('(.+?)'\)", onclick)
            if m:
                group_ids.append(m.group(1))
        numbers_url = urljoin(BASE_URL, "portal/sms/received/getsms/number")
        sms_url = urljoin(BASE_URL, "portal/sms/received/getsms/number/sms")

        for group_id in group_ids:
            numbers_payload = {"start": from_date_str, "end": to_date_str, "range": group_id, "_token": csrf_token}
            numbers_response = await client.post(numbers_url, headers=headers, data=numbers_payload, timeout=30.0)
            numbers_soup = BeautifulSoup(numbers_response.text, "html.parser")
            number_divs = numbers_soup.select("div[onclick*='getDetialsNumber']")
            if not number_divs:
                continue
            phone_numbers = [div.text.strip() for div in number_divs]

            for phone_number in phone_numbers:
                sms_payload = {"start": from_date_str, "end": to_date_str, "Number": phone_number, "Range": group_id, "_token": csrf_token}
                sms_response = await client.post(sms_url, headers=headers, data=sms_payload, timeout=30.0)
                sms_soup = BeautifulSoup(sms_response.text, "html.parser")
                final_sms_cards = sms_soup.find_all("div", class_="card-body")
                for card in final_sms_cards:
                    sms_text_p = card.find("p", class_="mb-0")
                    if sms_text_p:
                        sms_text = sms_text_p.get_text(separator="\n").strip()
                        date_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
                        country_name = group_id.strip()
                        service = "Unknown"
                        lower_sms_text = sms_text.lower()
                        for service_name, keywords in SERVICE_KEYWORDS.items():
                            if any(keyword in lower_sms_text for keyword in keywords):
                                service = service_name
                                break
                        code_match = re.search(r"(\d{3}-\d{3})", sms_text) or re.search(r"\b(\d{4,8})\b", sms_text)
                        code = code_match.group(1) if code_match else "N/A"
                        unique_id = f"{phone_number}-{sms_text}"
                        flag = COUNTRY_FLAGS.get(country_name, "🏴‍☠️")
                        all_messages.append({
                            "id": unique_id,
                            "time": date_str,
                            "number": phone_number,
                            "country": country_name,
                            "flag": flag,
                            "service": service,
                            "code": code,
                            "full_sms": sms_text
                        })
        return all_messages

    except httpx.RequestError as e:
        print("❌ Network issue (httpx):", e)
        return []
    except Exception as e:
        print("❌ Error fetching/processing SMS:", e)
        traceback.print_exc()
        return []

# ----------------- Telegram send -----------------
def escape_markdown(text):
    escape_chars = r'\_*[]()~`>#+-=|{}.!'
    return re.sub(f'([{re.escape(escape_chars)}])', r'\\\1', str(text))

async def send_telegram_message(context: ContextTypes.DEFAULT_TYPE, chat_id: str, message_data: dict):
    try:
        time_str = message_data.get("time", "N/A")
        number_str = message_data.get("number", "N/A")
        country_name = message_data.get("country", "N/A")
        flag_emoji = message_data.get("flag", "🏴‍☠️")
        service_name = message_data.get("service", "N/A")
        code_str = message_data.get("code", "N/A")
        full_sms_text = message_data.get("full_sms", "N/A")
        service_emoji = SERVICE_EMOJIS.get(service_name, "❓")

        full_message = (
            f"🔔 *You have successfully received OTP*\n\n"
            f"📞 *Number:* `{escape_markdown(number_str)}`\n"
            f"🔑 *Code:* `{escape_markdown(code_str)}`\n"
            f"🏆 *Service:* {service_emoji} {escape_markdown(service_name)}\n"
            f"🌎 *Country:* {escape_markdown(country_name)} {flag_emoji}\n"
            f"⏳ *Time:* `{escape_markdown(time_str)}`\n\n"
            f"💬 *Message:*\n"
            f"```\n{full_sms_text}\n```"
        )
        await context.bot.send_message(chat_id=chat_id, text=full_message, parse_mode="MarkdownV2")
    except Exception as e:
        print("❌ Error sending message:", e)

# ----------------- Main job -----------------
async def check_sms_job(context: ContextTypes.DEFAULT_TYPE):
    print(f"\n--- [{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}] Checking for new messages ---")
    cookies_payload = load_cookies_file()
if not cookies_payload or cookies_expired(cookies_payload):
    # dapatkan cookies via Playwright (akan menjalankan login & menyimpan cookie)
    headless_mode = True  # atau False saat butuh solve captcha manual
    cookies_list, csrf_token, page_html = await playwright_login_and_extract(USERNAME, PASSWORD, headless=headless_mode)
    if not cookies_list:
        print("❌ Failed to obtain cookies via Playwright. Aborting this cycle.")
        # tambah logging page_html untuk debugging (opsional)
        if page_html:
            print("---- page_html preview ----")
            print(page_html[:2000])
        return
    save_cookies_file(cookies_list, csrf_token)
    cookies_payload = load_cookies_file()

# pastikan cookies_payload bukan None sekarang
if not cookies_payload:
    print("❌ cookies_payload is still None after Playwright login. Aborting.")
    return
    cookies_list = cookies_payload.get("cookies", [])
    csrf_token = cookies_payload.get("csrf_token")
    cookie_header = cookies_list_to_cookie_header(cookies_list)
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Referer": BASE_URL,
        "Cookie": cookie_header
    }

    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        try:
            messages = await fetch_sms_from_api_with_cookies(client, headers, csrf_token)
            if not messages:
                print("✔️ No new messages.")
                return

            processed_ids = load_processed_ids()
            chat_ids_to_send = load_chat_ids()
            new_found = 0
            for msg in reversed(messages):
                if msg["id"] not in processed_ids:
                    new_found += 1
                    print("✔️ New message:", msg["number"])
                    for chat_id in chat_ids_to_send:
                        await send_telegram_message(context, chat_id, msg)
                    save_processed_id(msg["id"])
            if new_found > 0:
                print(f"✅ Sent {new_found} new messages.")
        except Exception as e:
            print("❌ Error in main job loop:", e)
            traceback.print_exc()

# ----------------- Telegram commands -----------------
async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if str(user_id) in ADMIN_CHAT_IDS:
        await update.message.reply_text(
            "Welcome Admin!\n"
            "/add_chat <chat_id> - Add chat ID\n"
            "/remove_chat <chat_id> - Remove chat ID\n"
            "/list_chats - List chat IDs"
        )
    else:
        await update.message.reply_text("Sorry, you are not authorized to use this bot.")

async def add_chat_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if str(user_id) not in ADMIN_CHAT_IDS:
        await update.message.reply_text("Only admins can use this.")
        return
    try:
        new_chat = context.args[0]
        chat_ids = load_chat_ids()
        if new_chat not in chat_ids:
            chat_ids.append(new_chat)
            save_chat_ids(chat_ids)
            await update.message.reply_text(f"✅ Added {new_chat}")
        else:
            await update.message.reply_text("⚠️ Chat ID already exists.")
    except Exception:
        await update.message.reply_text("Usage: /add_chat <chat_id>")

async def remove_chat_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if str(user_id) not in ADMIN_CHAT_IDS:
        await update.message.reply_text("Only admins can use this.")
        return
    try:
        to_remove = context.args[0]
        chat_ids = load_chat_ids()
        if to_remove in chat_ids:
            chat_ids.remove(to_remove)
            save_chat_ids(chat_ids)
            await update.message.reply_text(f"✅ Removed {to_remove}")
        else:
            await update.message.reply_text("Chat ID not found.")
    except Exception:
        await update.message.reply_text("Usage: /remove_chat <chat_id>")

async def list_chats_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if str(user_id) not in ADMIN_CHAT_IDS:
        await update.message.reply_text("Only admins can use this.")
        return
    chat_ids = load_chat_ids()
    if chat_ids:
        message = "📜 Currently registered chat IDs are:\n" + "\n".join(map(str, chat_ids))
        await update.message.reply_text(message)
    else:
        await update.message.reply_text("No chat IDs registered.")

# ----------------- Entry point -----------------
def main():
    if not ADMIN_CHAT_IDS:
        print("❌ ADMIN_CHAT_IDS is empty. Please set admin IDs.")
        return
    if YOUR_BOT_TOKEN == "YOUR_TELEGRAM_BOT_TOKEN":
        print("❌ Please set YOUR_BOT_TOKEN in the script before running.")
        return
    print("🚀 Starting iVasms Playwright Bot...")

    application = Application.builder().token(YOUR_BOT_TOKEN).build()
    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CommandHandler("add_chat", add_chat_command))
    application.add_handler(CommandHandler("remove_chat", remove_chat_command))
    application.add_handler(CommandHandler("list_chats", list_chats_command))

    job_queue = application.job_queue
    job_queue.run_repeating(check_sms_job, interval=POLLING_INTERVAL_SECONDS, first=5)

    print(f"✅ Running. Polling every {POLLING_INTERVAL_SECONDS} seconds.")
    application.run_polling()

if __name__ == "__main__":
    main()