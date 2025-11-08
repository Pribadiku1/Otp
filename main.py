# -*- coding: utf-8 -*-
"""
OrangeCarrier -> Telegram OTP Forwarder Bot
- Designed to login with email/password
- Scrape / find messages / OTPs and forward to Telegram chats
- Admin Telegram commands to manage chat IDs
"""

import asyncio
import re
import httpx
from bs4 import BeautifulSoup
import time
import json
import os
import traceback
from urllib.parse import urljoin, urlparse
from datetime import datetime, timedelta

from telegram.ext import Application, CommandHandler, ContextTypes
from telegram import Update

# ----------------- CONFIG -----------------
# Telegram bot token (fill yours)
YOUR_BOT_TOKEN = "8054353237:AAFYfqRso0aN8dFYmNP2o_RWLF9fKwKXYZ0"

# Admins (Telegram user ids as strings)
ADMIN_CHAT_IDS = ["6190125375"]

# initial chat ids to seed (channels or personal chat ids)
INITIAL_CHAT_IDS = ["-1002580267867"]

# Orange Carrier site config
LOGIN_URL = "https://orangecarrier.com/login"
BASE_URL = "https://orangecarrier.com/"

# Polling interval (seconds)
POLLING_INTERVAL_SECONDS = 5

# Files
STATE_FILE = "processed_sms_ids.json"
CHAT_IDS_FILE = "chat_ids.json"

# Country flags (partial list — extend as needed)
COUNTRY_FLAGS = {
    "Unknown Country": "🏴‍☠️", "United States": "🇺🇸", "United Kingdom": "🇬🇧",
    "Bangladesh": "🇧🇩", "India": "🇮🇳", "Pakistan": "🇵🇰", "France": "🇫🇷",
    "Germany": "🇩🇪", "Spain": "🇪🇸", "Nigeria": "🇳🇬"
}

# Service keywords & emojis (extend as needed)
SERVICE_KEYWORDS = {
    "Facebook": ["facebook"], "Google": ["gmail", "google"], "WhatsApp": ["whatsapp"],
    "Telegram": ["telegram"], "Instagram": ["instagram"], "Unknown": ["unknown"]
}
SERVICE_EMOJIS = {
    "Telegram": "📩", "WhatsApp": "🟢", "Facebook": "📘", "Google": "🔍", "Unknown": "❓"
}

# Your OrangeCarrier credentials
USERNAME = "mdsajibvai095@gmail.com"
PASSWORD = "sojibbro22@@##"
# ------------------------------------------

# ---------------- Helpers: chat ids ----------------
def load_chat_ids():
    if not os.path.exists(CHAT_IDS_FILE):
        with open(CHAT_IDS_FILE, 'w') as f:
            json.dump(INITIAL_CHAT_IDS, f)
        return INITIAL_CHAT_IDS.copy()
    try:
        with open(CHAT_IDS_FILE, 'r') as f:
            data = json.load(f)
            return data if isinstance(data, list) else INITIAL_CHAT_IDS.copy()
    except Exception:
        return INITIAL_CHAT_IDS.copy()

def save_chat_ids(chat_ids):
    with open(CHAT_IDS_FILE, 'w') as f:
        json.dump(chat_ids, f, indent=2)
# ---------------------------------------------------

# ---------------- Helpers: processed ids ----------------
def load_processed_ids():
    if not os.path.exists(STATE_FILE):
        return set()
    try:
        with open(STATE_FILE, 'r') as f:
            data = json.load(f)
            return set(data if isinstance(data, list) else [])
    except Exception:
        return set()

def save_processed_id(sms_id):
    processed = load_processed_ids()
    processed.add(sms_id)
    with open(STATE_FILE, 'w') as f:
        json.dump(list(processed), f, indent=2)
# ---------------------------------------------------------

def escape_markdown(text: str):
    escape_chars = r'\_*[]()~`>#+-=|{}.!'
    return re.sub(f'([{re.escape(escape_chars)}])', r'\\\1', str(text))

# ---------------- Telegram command handlers ----------------
async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    if str(user_id) in ADMIN_CHAT_IDS:
        await update.message.reply_text(
            "Welcome Admin!\n"
            "Commands:\n"
            "/add_chat <chat_id>\n"
            "/remove_chat <chat_id>\n"
            "/list_chats"
        )
    else:
        await update.message.reply_text("Sorry, you are not authorized.")

async def add_chat_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    if str(user_id) not in ADMIN_CHAT_IDS:
        await update.message.reply_text("Only admins can use this.")
        return
    try:
        new_chat_id = context.args[0]
        chat_ids = load_chat_ids()
        if new_chat_id not in chat_ids:
            chat_ids.append(new_chat_id)
            save_chat_ids(chat_ids)
            await update.message.reply_text(f"✅ Chat ID {new_chat_id} added.")
        else:
            await update.message.reply_text("Chat ID already present.")
    except Exception:
        await update.message.reply_text("Usage: /add_chat <chat_id>")

async def remove_chat_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    if str(user_id) not in ADMIN_CHAT_IDS:
        await update.message.reply_text("Only admins can use this.")
        return
    try:
        rem_chat_id = context.args[0]
        chat_ids = load_chat_ids()
        if rem_chat_id in chat_ids:
            chat_ids.remove(rem_chat_id)
            save_chat_ids(chat_ids)
            await update.message.reply_text(f"✅ Chat ID {rem_chat_id} removed.")
        else:
            await update.message.reply_text("Chat ID not found.")
    except Exception:
        await update.message.reply_text("Usage: /remove_chat <chat_id>")

async def list_chats_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    if str(user_id) not in ADMIN_CHAT_IDS:
        await update.message.reply_text("Only admins can use this.")
        return
    chat_ids = load_chat_ids()
    if not chat_ids:
        await update.message.reply_text("No chat IDs saved.")
        return
    try:
        message = "Registered chat IDs:\n" + "\n".join([f"- `{escape_markdown(str(cid))}`" for cid in chat_ids])
        await update.message.reply_text(message, parse_mode='MarkdownV2')
    except Exception:
        await update.message.reply_text("Registered chat IDs:\n" + "\n".join(map(str, chat_ids)))

# ---------------- Core: Scraping / fetching messages ----------------
async def discover_messages_page(client: httpx.AsyncClient, dashboard_html: str, current_url: str):
    """
    Try to find a page or endpoint that likely contains messages.
    Strategies:
    - Find <a href> with keywords 'sms', 'message', 'inbox', 'received'
    - Find script tags containing '/api/' or '/messages' endpoints
    - Return absolute URL or None
    """
    soup = BeautifulSoup(dashboard_html, 'html.parser')

    # 1) Find anchor links with keywords
    keywords = ['sms', 'message', 'inbox', 'received', 'messages', 'otp']
    for a in soup.find_all('a', href=True):
        href = a['href'].lower()
        text = (a.get_text() or "").lower()
        if any(k in href for k in keywords) or any(k in text for k in keywords):
            candidate = urljoin(current_url, a['href'])
            return candidate

    # 2) Find forms that might POST to message endpoints
    for form in soup.find_all('form', action=True):
        action = form['action'].lower()
        if any(k in action for k in keywords):
            return urljoin(current_url, form['action'])

    # 3) Search script tags for JSON endpoints
    for script in soup.find_all('script'):
        if script.string:
            text = script.string
            # look for /api/... or /messages/ and extract a plausible URL
            m = re.search(r'(["\'])(/[^"\']*(?:sms|message|messages|received|inbox)[^"\']*)\1', text, flags=re.I)
            if m:
                return urljoin(current_url, m.group(2))

    # 4) Try common dashboard paths
    common_paths = ['portal/messages', 'messages', 'inbox', 'dashboard/messages', 'portal/sms', 'sms/received']
    for p in common_paths:
        candidate = urljoin(BASE_URL, p)
        # quick HEAD to see if exists
        try:
            r = await client.head(candidate, timeout=10.0, follow_redirects=True)
            if r.status_code == 200:
                return candidate
        except Exception:
            continue

    return None

def extract_possible_sms_blocks(html_text: str):
    """
    Parse the HTML and find blocks that look like SMS messages.
    Strategies:
    - Look for elements with class names containing 'message', 'sms', 'card', 'list-group-item'
    - Search for <p>, <pre>, <div> with texting patterns
    """
    soup = BeautifulSoup(html_text, 'html.parser')
    blocks = []

    # check for cards/list items
    candidates = []
    for cls in ['message', 'sms', 'card', 'item', 'inbox', 'received', 'list-group-item']:
        candidates += soup.find_all(attrs={"class": re.compile(cls, flags=re.I)})
    # also sections with <p> that contain digits / code patterns
    p_tags = soup.find_all('p')
    for p in p_tags:
        text = p.get_text(strip=True)
        # heuristic: contains at least one number and at least 6 chars
        if text and (re.search(r'\d', text)) and len(text) > 6:
            candidates.append(p)

    # dedupe and collect text
    seen = set()
    for node in candidates:
        txt = node.get_text(separator='\n', strip=True)
        if not txt:
            continue
        if txt in seen:
            continue
        seen.add(txt)
        blocks.append(txt)

    # fallback: whole page text split by lines
    if not blocks:
        full = soup.get_text(separator='\n')
        lines = [l.strip() for l in full.splitlines() if l.strip()]
        # get lines that look like OTP/messages
        for ln in lines:
            if len(ln) > 10 and re.search(r'\d', ln):
                blocks.append(ln)

    return blocks

def find_code_and_service(text: str):
    """
    Find OTP/code in text and identify possible service.
    Returns (code, service_name)
    """
    # common OTP patterns
    patterns = [
        r'\b(\d{4,8})\b',          # 4-8 digits
        r'\b(\d{3}-\d{3})\b',      # 123-456
        r'([A-Z0-9]{6,8})',        # alphanumeric codes
    ]
    code = None
    for p in patterns:
        m = re.search(p, text)
        if m:
            code = m.group(1)
            break

    # detect service keyword
    lower = text.lower()
    service = "Unknown"
    for sname, keywords in SERVICE_KEYWORDS.items():
        for kw in keywords:
            if kw in lower:
                service = sname
                break
        if service != "Unknown":
            break

    return code or "N/A", service

async def fetch_messages_from_page(client: httpx.AsyncClient, url: str, headers: dict):
    """
    GET the page and try to extract message blocks
    """
    try:
        r = await client.get(url, headers=headers, timeout=20.0)
        r.raise_for_status()
        blocks = extract_possible_sms_blocks(r.text)
        results = []
        for b in blocks:
            code, service = find_code_and_service(b)
            # attempt to find phone numbers
            phone_match = re.search(r'(\+?\d{6,15})', b)
            phone = phone_match.group(1) if phone_match else "Unknown"
            unique_id = f"{phone}-{hash(b)}"
            results.append({
                "id": unique_id,
                "time": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
                "number": phone,
                "country": "Unknown Country",
                "flag": COUNTRY_FLAGS.get("Unknown Country", "🏴‍☠️"),
                "service": service,
                "code": code,
                "full_sms": b
            })
        return results
    except Exception as e:
        print(f"❌ fetch_messages_from_page error for {url}: {e}")
        return []

async def fetch_sms_from_orangecarrier(client: httpx.AsyncClient, headers: dict, login_response: httpx.Response):
    """
    Try multiple strategies to gather messages after successful login:
    1) Discover a messages page and parse it
    2) Search dashboard for inline messages
    3) Try any discovered API endpoints
    """
    try:
        # 1) Dashboard parsing
        dashboard_html = login_response.text
        current_url = str(login_response.url)
        messages = []

        # Discover messages page/endpoint
        messages_page = await discover_messages_page(client, dashboard_html, current_url)
        if messages_page:
            print(f"ℹ️ Found messages page: {messages_page}")
            messages += await fetch_messages_from_page(client, messages_page, headers)

        # 2) Also try scanning dashboard itself
        print("ℹ️ Scanning dashboard page for message-like content...")
        blocks = extract_possible_sms_blocks(dashboard_html)
        for b in blocks:
            code, service = find_code_and_service(b)
            phone_match = re.search(r'(\+?\d{6,15})', b)
            phone = phone_match.group(1) if phone_match else "Unknown"
            unique_id = f"{phone}-{hash(b)}"
            messages.append({
                "id": unique_id,
                "time": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
                "number": phone,
                "country": "Unknown Country",
                "flag": COUNTRY_FLAGS.get("Unknown Country", "🏴‍☠️"),
                "service": service,
                "code": code,
                "full_sms": b
            })

        # 3) Try to detect JSON endpoints in scripts and hit them
        # Look for /api/ or /messages endpoints in dashboard html
        scripts_text = " ".join([s.string or "" for s in BeautifulSoup(dashboard_html, 'html.parser').find_all('script')])
        api_matches = re.findall(r'(["\'])(/[^"\']*(?:api|messages|sms|received|inbox)[^"\']*)\1', scripts_text, flags=re.I)
        for m in api_matches:
            endpoint = urljoin(BASE_URL, m[1])
            try:
                print(f"ℹ️ Trying API endpoint: {endpoint}")
                r = await client.get(endpoint, headers=headers, timeout=20.0)
                if r.status_code == 200:
                    # if JSON, parse
                    try:
                        data = r.json()
                        # attempt to extract messages if structure present
                        if isinstance(data, list):
                            for item in data:
                                text = item.get('message') or item.get('text') or str(item)
                                code, service = find_code_and_service(text)
                                phone = item.get('number') or item.get('from') or "Unknown"
                                uid = f"{phone}-{hash(text)}"
                                messages.append({
                                    "id": uid,
                                    "time": item.get('time') or datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
                                    "number": phone,
                                    "country": item.get('country', 'Unknown Country'),
                                    "flag": COUNTRY_FLAGS.get(item.get('country', 'Unknown Country'), "🏴‍☠️"),
                                    "service": service,
                                    "code": code,
                                    "full_sms": text
                                })
                        else:
                            # fallback: search json text fields
                            txt = json.dumps(data)
                            code, service = find_code_and_service(txt)
                            uid = f"api-{hash(txt)}"
                            messages.append({
                                "id": uid,
                                "time": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
                                "number": "Unknown",
                                "country": "Unknown Country",
                                "flag": COUNTRY_FLAGS.get("Unknown Country", "🏴‍☠️"),
                                "service": service,
                                "code": code,
                                "full_sms": txt
                            })
                    except ValueError:
                        # not json — treat as html
                        msgs = extract_possible_sms_blocks(r.text)
                        for b in msgs:
                            code, service = find_code_and_service(b)
                            phone_match = re.search(r'(\+?\d{6,15})', b)
                            phone = phone_match.group(1) if phone_match else "Unknown"
                            uid = f"{phone}-{hash(b)}"
                            messages.append({
                                "id": uid,
                                "time": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
                                "number": phone,
                                "country": "Unknown Country",
                                "flag": COUNTRY_FLAGS.get("Unknown Country", "🏴‍☠️"),
                                "service": service,
                                "code": code,
                                "full_sms": b
                            })
            except Exception:
                continue

        # dedupe by id
        unique = {}
        for m in messages:
            unique[m['id']] = m
        return list(unique.values())

    except Exception as e:
        print(f"❌ Error fetching SMS from OrangeCarrier: {e}")
        traceback.print_exc()
        return []

# ---------------- Send message ----------------
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
        await context.bot.send_message(chat_id=chat_id, text=full_message, parse_mode='MarkdownV2')
    except Exception as e:
        print(f"❌ Error sending to {chat_id}: {e}")

# ---------------- The job: login then fetch ----------------
async def check_sms_job(context: ContextTypes.DEFAULT_TYPE):
    print(f"\n--- [{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}] Checking for new messages ---")
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
    }

    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        try:
            # 1) GET login page to get CSRF / form tokens
            print("ℹ️ Loading login page...")
            login_page = await client.get(LOGIN_URL, headers=headers)
            login_page.raise_for_status()
            soup = BeautifulSoup(login_page.text, 'html.parser')

            # Attempt to find token input name (_token, csrf_token, csrf)
            form = soup.find('form')
            token_name = None
            token_value = None

            if form:
                # fill form fields
                token_input = form.find('input', {'name': re.compile(r'(_token|csrf_token|csrf|token)', flags=re.I)})
                if token_input and token_input.get('value'):
                    token_name = token_input.get('name')
                    token_value = token_input.get('value')

            # also try meta tag
            if not token_value:
                meta = soup.find('meta', attrs={'name': re.compile(r'csrf', flags=re.I)})
                if meta and meta.get('content'):
                    token_value = meta.get('content')
                    token_name = meta.get('name') or '_token'

            # prepare payload
            login_data = {}
            # common field names
            possible_email_fields = ['email', 'username', 'user', 'login_email']
            possible_password_fields = ['password', 'pass', 'login_password']
            # find names in form
            if form:
                # prefer explicit input names if present
                email_inp = form.find('input', {'type': 'email'}) or form.find('input', {'name': re.compile('email', flags=re.I)})
                pass_inp = form.find('input', {'type': 'password'}) or form.find('input', {'name': re.compile('pass', flags=re.I)})
                if email_inp and email_inp.get('name'):
                    login_data[email_inp.get('name')] = USERNAME
                else:
                    login_data['email'] = USERNAME
                if pass_inp and pass_inp.get('name'):
                    login_data[pass_inp.get('name')] = PASSWORD
                else:
                    login_data['password'] = PASSWORD
            else:
                # fallback names
                login_data['email'] = USERNAME
                login_data['password'] = PASSWORD

            if token_name and token_value:
                login_data[token_name] = token_value

            # Determine login post URL (form action or LOGIN_URL)
            post_url = LOGIN_URL
            if form and form.get('action'):
                post_url = urljoin(str(login_page.url), form.get('action'))

            print(f"ℹ️ Submitting login to: {post_url}")
            login_res = await client.post(post_url, data=login_data, headers=headers)
            # Some sites redirect to dashboard on success
            if "login" in str(login_res.url).lower() or login_res.status_code in (401, 403):
                print("❌ Login seems to have failed. Check credentials or change selectors.")
                return
            print("✅ Login successful (or at least not on login page).")

            # Now fetch SMS/messages using helper
            messages = await fetch_sms_from_orangecarrier(client, headers, login_res)

            if not messages:
                print("✔️ No messages extracted.")
                return

            processed = load_processed_ids()
            chat_ids = load_chat_ids()
            new_count = 0
            for msg in messages:
                if msg['id'] not in processed:
                    new_count += 1
                    print(f"✔️ New message -> {msg['number']} | code: {msg['code']}")
                    for cid in chat_ids:
                        await send_telegram_message(context, cid, msg)
                    save_processed_id(msg['id'])

            if new_count > 0:
                print(f"✅ Sent {new_count} new messages to Telegram.")
            else:
                print("✔️ No new (unprocessed) messages.")

        except httpx.RequestError as e:
            print(f"❌ Network issue: {e}")
        except Exception as e:
            print(f"❌ Error in check_sms_job: {e}")
            traceback.print_exc()

# ---------------- Main ----------------
def main():
    print("🚀 OrangeCarrier -> Telegram Bot starting...")
    if not ADMIN_CHAT_IDS:
        print("!!! No admin IDs set. Exiting.")
        return

    application = Application.builder().token(YOUR_BOT_TOKEN).build()

    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CommandHandler("add_chat", add_chat_command))
    application.add_handler(CommandHandler("remove_chat", remove_chat_command))
    application.add_handler(CommandHandler("list_chats", list_chats_command))

    job_queue = application.job_queue
    job_queue.run_repeating(check_sms_job, interval=POLLING_INTERVAL_SECONDS, first=2)

    print(f"🕒 Polling every {POLLING_INTERVAL_SECONDS} seconds.")
    application.run_polling()

if __name__ == "__main__":
    main()