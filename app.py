# -*- coding: utf-8 -*-
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
import pandas as pd
import os
import json
import plotly
import plotly.express as px
from datetime import datetime, timedelta, timezone
import requests
from lxml import html
import random
import time
import uuid
import subprocess
import sys
import logging
import flask_socketio
from flask_socketio import emit
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import threading
import re
import locale
from functools import wraps
from urllib.parse import urlparse

# --- Настройка локали ---
try: locale.setlocale(locale.LC_TIME, 'ru_RU.UTF-8')
except locale.Error:
    try: locale.setlocale(locale.LC_TIME, 'Russian_Russia.1251')
    except locale.Error: logging.warning("Не удалось установить русскую локаль.")

# --- Инициализация Flask и расширений ---
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'your_secure_secret_key_here_CHANGE_ME')
socketio = flask_socketio.SocketIO(app, async_mode='threading')
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "Пожалуйста, войдите."
login_manager.login_message_category = "info"

# --- Настройка логирования ---
log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
logging.basicConfig(filename='parser.log', level=logging.INFO, format=log_format, encoding='utf-8')
app.logger.setLevel(logging.INFO)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter(log_format))
if not logging.getLogger().hasHandlers():
    logging.getLogger().addHandler(console_handler)
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.WARNING)

# --- Константы ---
DATA_FOLDER = 'data'; CONFIG_FILE = 'competitors.json'; USERS_FILE = 'users.json'
PARSER_SCRIPT = 'competitor_parser.py'; PROXY_FILE = 'proxies.txt'
FLAGS_DIR = 'flags' # Папка для флагов паузы
DATE_FORMAT = '%d.%m.%Y %H:%M:%S'; DATE_FORMAT_SHORT = '%d.%m.%Y'
PROXY_TEST_URL = 'https://httpbin.org/ip'; PROXY_TEST_TIMEOUT = 10

# === НАСТРОЙКА РОЛЕЙ И ПРАВ ДОСТУПА ===
ROLES_PERMISSIONS = {
    'Admin': ['index', 'competitors', 'statistics', 'users', 'proxies', 'add_competitor', 'edit_competitor', 'delete_competitor', 'manual_parse', 'pause_parse', 'resume_parse', 'test_selector_route', 'test_sitemap_route', 'get_data', 'competitors_api', 'refresh_stats_route', 'add_user', 'edit_user', 'delete_user', 'change_password', 'logout', 'connect', 'disconnect', 'get_parsing_status', 'get_stats', 'start_proxy_test'],
    'Editor': ['index', 'competitors', 'statistics', 'add_competitor', 'edit_competitor', 'delete_competitor', 'manual_parse', 'pause_parse', 'resume_parse', 'test_selector_route', 'test_sitemap_route', 'get_data', 'competitors_api', 'refresh_stats_route', 'change_password', 'logout', 'connect', 'disconnect', 'get_parsing_status', 'get_stats'],
    'Viewer': ['index', 'statistics', 'get_data', 'competitors_api', 'refresh_stats_route', 'change_password', 'logout', 'connect', 'disconnect', 'get_parsing_status', 'get_stats']
}
DEFAULT_ROLE = 'Viewer'; ADMIN_USERNAME = 'admin'

# --- Глобальные переменные ---
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
]
PROXIES = []
parsing_processes = {}

# --- Загрузка прокси ---
def load_proxies_from_file(filepath=PROXY_FILE):
    proxies_list = [];
    if not os.path.exists(filepath): logging.warning(f"Файл прокси '{filepath}' не найден."); return proxies_list
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f):
                line = line.strip();
                if not line or line.startswith('#'): continue
                parts = line.split(':')
                if len(parts) == 4: ip, port, login, password = parts; proxy_url = f"http://{login}:{password}@{ip}:{port}"; proxies_list.append({'http': proxy_url, 'https': proxy_url, 'original_string': line})
                else: logging.warning(f"Неверный формат строки {line_num + 1} в '{filepath}': '{line}'.")
        logging.info(f"Загружено {len(proxies_list)} прокси из '{filepath}'.")
    except Exception as e: logging.error(f"Ошибка чтения '{filepath}': {e}", exc_info=True)
    return proxies_list

# --- Модель пользователя ---
class User(UserMixin):
    def __init__(self, id, username, password_hash, roles=None):
        self.id=id; self.username=username; self.password_hash=password_hash
        if roles is None: self.roles=[DEFAULT_ROLE]
        elif isinstance(roles,list) and roles: self.roles=[r for r in roles if r in ROLES_PERMISSIONS] or [DEFAULT_ROLE]
        else: self.roles=[DEFAULT_ROLE]
        if self.username==ADMIN_USERNAME and 'Admin' not in self.roles: self.roles.append('Admin')
    def has_role(self,role_name): return role_name in self.roles
    def can(self,permission_name):
        if self.username==ADMIN_USERNAME: return True
        return any(permission_name in ROLES_PERMISSIONS.get(role,[]) for role in self.roles)

# --- Загрузка/Сохранение пользователей ---
def load_users():
    if not os.path.exists(USERS_FILE):
        dus={'1':{'username':ADMIN_USERNAME,'password_hash':generate_password_hash('admin'),'roles':['Admin']}};
        try: f=open(USERS_FILE,'w',encoding='utf-8'); json.dump(dus,f,ensure_ascii=False,indent=4); f.close(); logging.info(f"'{USERS_FILE}' создан."); return dus
        except IOError as e: logging.error(f"Не создан '{USERS_FILE}': {e}"); return {}
    try:
        with open(USERS_FILE,'r',encoding='utf-8') as f: users=json.load(f);
        if not users: logging.warning(f"'{USERS_FILE}' пуст."); return {}
        upd=False;
        for uid,udata in users.items():
            if 'roles' not in udata: udata['roles']=['Admin'] if udata.get('username')==ADMIN_USERNAME else [DEFAULT_ROLE]; upd=True
            if udata.get('username')==ADMIN_USERNAME and 'Admin' not in udata['roles']: udata['roles'].append('Admin'); upd=True
        if upd: logging.info("Обновлен users.json."); save_users(users);
        return users
    except json.JSONDecodeError as e: logging.error(f"Ошибка JSON '{USERS_FILE}': {e}"); return {}
    except Exception as e: logging.error(f"Ошибка загрузки '{USERS_FILE}': {e}"); return {}

def save_users(users):
    try: f=open(USERS_FILE,'w',encoding='utf-8'); json.dump(users,f,ensure_ascii=False,indent=4); f.close()
    except Exception as e: logging.error(f"Ошибка сохранения '{USERS_FILE}': {e}")

@login_manager.user_loader
def load_user(user_id): users=load_users(); ud=users.get(user_id); return User(user_id,ud.get('username'),ud.get('password_hash'),ud.get('roles')) if ud else None

# --- Декоратор проверки прав ---
def permission_required(permission_name):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args,**kwargs):
            if not current_user.is_authenticated: return login_manager.unauthorized()
            if not current_user.can(permission_name): logging.warning(f"Доступ '{current_user.username}' к '{permission_name}' запрещен."); flash('Нет прав.','danger'); return redirect(url_for('index'))
            return f(*args,**kwargs)
        return decorated_function
    return decorator

# --- Функции форматирования и утилиты ---
def format_datetime(date_obj, fmt=DATE_FORMAT):
    if pd.isnull(date_obj) or not date_obj: return ""
    try:
        if isinstance(date_obj, (datetime, pd.Timestamp)):
            dt_to_format = date_obj.tz_convert(None) if date_obj.tzinfo else date_obj
            return dt_to_format.strftime(fmt)
        elif isinstance(date_obj, str):
            try: dt = pd.to_datetime(date_obj); return format_datetime(dt, fmt)
            except (ValueError, TypeError):
                try: dt = pd.to_datetime(date_obj, dayfirst=True); return format_datetime(dt, fmt)
                except (ValueError, TypeError): logging.warning(f"Не формат '{date_obj}'"); return date_obj
        elif hasattr(date_obj, 'strftime'): return date_obj.strftime(fmt)
        else: return str(date_obj)
    except Exception as e: logging.error(f"Ошибка форматирования '{date_obj}': {e}"); return str(date_obj)

def format_date_short(date_obj): return format_datetime(date_obj, fmt=DATE_FORMAT_SHORT)
app.jinja_env.filters['format_datetime'] = format_datetime

def get_random_headers(): ua=random.choice(USER_AGENTS) if USER_AGENTS else 'Mozilla/5.0'; return {'User-Agent':ua,'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8','Accept-Language':'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7','Connection':'keep-alive','Upgrade-Insecure-Requests':'1','Cache-Control':'max-age=0'}
def get_proxy(): return random.choice(PROXIES) if PROXIES else None

# --- Загрузка/сохранение конкурентов (С МИГРАЦИЕЙ СЕЛЕКТОРОВ и USE_PROXY) ---
def load_competitors():
    if not os.path.exists(CONFIG_FILE):
        logging.warning(f"'{CONFIG_FILE}' не найден, создается.")
        try: f=open(CONFIG_FILE,'w',encoding='utf-8'); json.dump({},f,ensure_ascii=False,indent=4); f.close(); return {}
        except IOError as e: logging.error(f"Не создан '{CONFIG_FILE}': {e}"); return {}
    try:
        with open(CONFIG_FILE,'r',encoding='utf-8') as f: comps=json.load(f)
        updated = False
        for name, cfg in comps.items():
            migrated_selectors = False
            old_selector_type = cfg.pop('selector_type', None)
            old_views_selector = cfg.pop('views_selector', None)
            old_date_selector = cfg.pop('date_selector', None)
            if old_selector_type or old_views_selector or old_date_selector: migrated_selectors=True; updated=True; default_type=old_selector_type if old_selector_type in ['xpath','css'] else 'xpath';
            if migrated_selectors:
                if 'views_selector_type' not in cfg: cfg['views_selector_type']=default_type
                if 'date_selector_type' not in cfg: cfg['date_selector_type']=default_type
                if 'views_selectors' not in cfg: cfg['views_selectors']=[old_views_selector] if old_views_selector else []
                if 'date_selectors' not in cfg: cfg['date_selectors']=[old_date_selector] if old_date_selector else []
                logging.info(f"Мигрированы селекторы для '{name}'.")
            if 'rss_url' in cfg: del cfg['rss_url']; updated = True
            if cfg.get('source_type')=='rss': cfg['source_type']='sitemap'; updated=True
            if 'source_url' in cfg and 'sitemap_urls' not in cfg: su=cfg.pop('source_url'); cfg['sitemap_urls']=[su] if su and isinstance(su,str) else []; updated=True
            elif 'sitemap_urls' not in cfg: cfg['sitemap_urls']=[]; updated=True
            if 'views_selector_type' not in cfg: cfg['views_selector_type']='xpath'; updated=True
            if 'date_selector_type' not in cfg: cfg['date_selector_type']='xpath'; updated=True
            if 'views_selectors' not in cfg: cfg['views_selectors']=[]; updated=True
            if 'date_selectors' not in cfg: cfg['date_selectors']=[]; updated=True
            if 'source_type' not in cfg: cfg['source_type']='sitemap'; updated=True
            if 'last_check' not in cfg: cfg['last_check']=None; updated=True
            if 'last_full_parse_stats' not in cfg: cfg['last_full_parse_stats']=None; updated=True
            if 'processed_urls' not in cfg: cfg['processed_urls']=[]; updated=True
            if 'use_proxy' not in cfg: cfg['use_proxy'] = False; updated = True
        if updated: logging.info("Обновлен формат competitors.json."); save_competitors(comps)
        return comps
    except json.JSONDecodeError as e: logging.error(f"Ошибка JSON '{CONFIG_FILE}': {e}"); return {}
    except Exception as e: logging.error(f"Ошибка загрузки '{CONFIG_FILE}': {e}"); return {}

def save_competitors(competitors):
    try: f=open(CONFIG_FILE,'w',encoding='utf-8'); json.dump(competitors,f,ensure_ascii=False,indent=4); f.close()
    except Exception as e: logging.error(f"Ошибка сохранения '{CONFIG_FILE}': {e}")

# --- Получение данных и статистики ---
def get_all_data():
    alldata=[];
    if not os.path.exists(DATA_FOLDER): logging.warning(f"'{DATA_FOLDER}' нет."); os.makedirs(DATA_FOLDER,exist_ok=True); return pd.DataFrame()
    files=[f for f in os.listdir(DATA_FOLDER) if f.endswith('.csv')]
    for file in files:
        fp=os.path.join(DATA_FOLDER,file)
        logging.debug(f"Чтение файла: {fp}")
        try:
            try: df=pd.read_csv(fp,sep=';',low_memory=False)
            except Exception: df=pd.read_csv(fp,sep=',',low_memory=False)
            if len(df.columns)<=1 and ',' in df.columns[0]: df=pd.read_csv(fp,sep=',',low_memory=False)
            parts=os.path.splitext(file)[0].split('_'); cname=parts[0] if parts else "unk"; dt_str=parts[-1] if len(parts)>1 else None
            try: cdate=pd.to_datetime(dt_str,format='%Y-%m-%d')
            except(ValueError,TypeError): cdate=pd.Timestamp(datetime.now().date()); logging.warning(f"Не извлечена дата из имени файла {file}")
            df['competitor']=cname
            if 'check_date' not in df.columns: df['check_date']=cdate
            else: df['check_date']=pd.to_datetime(df['check_date'],errors='coerce',dayfirst=True).fillna(cdate)
            if 'views' in df.columns:
                def parse_v(v):
                    if pd.isna(v): return 0; s=str(v).strip().replace(' ','').upper().replace(',','.'); m=1
                    if 'K' in s: m=1000; s=s.replace('K','')
                    elif 'M' in s: m=1000000; s=s.replace('M','')
                    s=re.sub(r'[^\d.]','',s);
                    try: return int(float(s)*m)
                    except ValueError: return 0
                df['views_num']=df['views'].apply(parse_v)
            else: df['views_num']=0
            if 'published_page' in df.columns: df['published_page_date']=pd.to_datetime(df['published_page'],errors='coerce')
            else: df['published_page_date']=pd.NaT
            alldata.append(df)
        except pd.errors.EmptyDataError: logging.warning(f"'{fp}' пуст.")
        except Exception as e: logging.error(f"Крит. ошибка '{fp}': {e}",exc_info=True)
    if alldata:
        try:
            cdf=pd.concat(alldata,ignore_index=True,sort=False);
            if 'url' in cdf.columns: cdf.dropna(subset=['url'],inplace=True)
            else: logging.warning("Нет колонки 'url'.")
            if 'title' in cdf.columns: cdf.dropna(subset=['title'],inplace=True)
            else: logging.warning("Нет колонки 'title'.")
            cdf['check_date'] = pd.to_datetime(cdf['check_date'], errors='coerce')
            cdf['published_page_date'] = pd.to_datetime(cdf['published_page_date'], errors='coerce')
            if 'views_num' in cdf.columns: cdf['views_num'] = pd.to_numeric(cdf['views_num'], errors='coerce').fillna(0).astype(int)
            else: cdf['views_num'] = 0
            logging.info(f"Загружено {len(cdf)} записей.")
            return cdf
        except Exception as e: logging.error(f"Ошибка concat/финал.обработки: {e}",exc_info=True); return pd.DataFrame()
    else: logging.info("Нет данных CSV."); return pd.DataFrame()

# --- Обновление Статуса для UI ---
def get_competitor_stats():
    comps=load_competitors(); stats=[]
    for name,cfg in comps.items():
        lc_ts=cfg.get('last_check'); lc_str=format_datetime(lc_ts) if lc_ts else "N/A"
        lfp_info=cfg.get('last_full_parse_stats'); lfp_str="N/A"
        if lfp_info and isinstance(lfp_info,dict): lfp_ts=lfp_info.get("timestamp"); lfp_p=lfp_info.get("processed_count",0); lfp_f=lfp_info.get("found_count",0); lfp_str=f"{format_datetime(lfp_ts)}(Н:{lfp_f},О:{lfp_p})" if lfp_ts else "N/A"
        elif cfg.get('last_full_parse'): lfp_str=f"{format_datetime(cfg.get('last_full_parse'))}(Ст.)"
        p_status="Неактивен"; p_details=""; is_paused=False; task_id=None
        if name in parsing_processes:
            p_info=parsing_processes[name]; task_id=p_info.get('task_id')
            t_alive=p_info.get('output_thread') and p_info['output_thread'].is_alive()
            p_alive=p_info.get('process') and p_info['process'].poll() is None
            is_paused = p_info.get('paused', False)
            if p_alive or t_alive:
                if is_paused: p_status = "На паузе"
                else: p_status = "Активен"
                st_str = p_info.get('start_time',''); pt = "Полн." if p_info.get('is_full') else "Инкр."; p_details = f"({pt},{st_str})"
            else:
                if name in parsing_processes: del parsing_processes[name]
        stats.append({'name':name, 'last_check':lc_str, 'last_full_parse_info':lfp_str,'parsing_status':p_status, 'parsing_details':p_details, 'is_paused': is_paused, 'task_id': task_id})
    return stats

# --- Функции тестирования ---
def test_selectors(url, selector, selector_type, retries=2):
    logging.info(f"Тест селектора: URL={url}, Тип={selector_type}")
    headers=get_random_headers(); proxies=get_proxy(); p_info=f"прокси {list(proxies.values())[0].split('@')[1]}" if proxies else "без прокси"
    for attempt in range(retries+1):
        try:
            resp=requests.get(url,headers=headers,proxies=proxies,timeout=20); resp.raise_for_status()
            resp.encoding=resp.apparent_encoding; tree=html.fromstring(resp.text)
            elems=tree.xpath(selector) if selector_type=='xpath' else tree.cssselect(selector)
            if not elems: return {'success':True,'results':[],'count':0,'message':'Не найдено.'}
            res=[el.text_content().strip() if hasattr(el,'text_content') else str(el).strip() for el in elems[:5]]
            logging.info(f"Тест ({p_info}) OK. {len(elems)} найдено."); return {'success':True,'results':res,'count':len(elems)}
        except requests.exceptions.RequestException as e:
            logging.warning(f"Поп.{attempt+1}: Ошибка {p_info} {url}: {e}")
            if attempt<retries: time.sleep(random.uniform(1,3)); proxies=get_proxy()
            else: return {'success':False,'error':f"Ошибка соединения: {str(e)}"}
        except Exception as e:
             logging.error(f"Ошибка теста {p_info} {url}: {e}",exc_info=True)
             if attempt<retries: time.sleep(random.uniform(1,3)); proxies=get_proxy()
             else: return {'success':False,'error':f"Ошибка: {str(e)}"}
    return {'success':False,'error':'Макс.попытки'}

def test_sitemap(sitemap_url):
    logging.info(f"Тест Sitemap: {sitemap_url}"); headers=get_random_headers(); proxies=get_proxy(); p_info=f"прокси {list(proxies.values())[0].split('@')[1]}" if proxies else "без прокси"
    try:
        resp=requests.get(sitemap_url,headers=headers,proxies=proxies,timeout=30,verify=True); resp.raise_for_status()
        ct=resp.headers.get('Content-Type','').lower();
        if 'xml' not in ct: logging.warning(f"Не XML '{ct}' ({p_info}) {sitemap_url}")
        resp.encoding=resp.apparent_encoding; content=resp.text
        try:
            root=html.fromstring(content.encode(resp.encoding),parser=html.etree.XMLParser(recover=True)); ns={'sm':'http://www.sitemaps.org/schemas/sitemap/0.9'}
            s_locs=root.xpath('//sm:sitemap/sm:loc/text()',namespaces=ns) or root.xpath('//sitemap/loc/text()')
            if s_locs: ents=[{'url':normalize_url(l,sitemap_url),'type':'sitemap'} for l in s_locs[:5]]; return {'success':True,'entries':ents,'count':len(s_locs),'is_index':True,'message':f'Index({len(s_locs)}).'}
            p_locs=root.xpath('//sm:url/sm:loc/text()',namespaces=ns) or root.xpath('//url/loc/text()')
            if p_locs:
                ents=[];
                for i,u_txt in enumerate(p_locs[:5]): u=normalize_url(u_txt,sitemap_url); lm_lst=root.xpath(f'(.//sm:url)[{i+1}]/sm:lastmod/text()',namespaces=ns) or root.xpath(f'(.//url)[{i+1}]/lastmod/text()'); lm=lm_lst[0] if lm_lst else 'N/A'; ents.append({'url':u,'lastmod':lm,'type':'page'})
                return {'success':True,'entries':ents,'count':len(p_locs),'is_index':False,'message':f'Карта({len(p_locs)}).'}
            logging.warning(f"Нет тегов ({p_info}) в '{sitemap_url}'."); return {'success':False,'error':'Неизв. структура.'}
        except Exception as e: logging.error(f"Ошибка парсинга XML ({p_info}) '{sitemap_url}': {e}",exc_info=True); return {'success':False,'error':f"Ошибка парсинга: {str(e)}"}
    except requests.exceptions.RequestException as e: logging.error(f"Ошибка соединения ({p_info}) '{sitemap_url}': {e}"); return {'success':False,'error':f"Ошибка соединения: {str(e)}"}
    except Exception as e: logging.error(f"Ошибка теста Sitemap ({p_info}) '{sitemap_url}': {e}",exc_info=True); return {'success':False,'error':f"Ошибка: {str(e)}"}

def test_proxy(proxy_dict, target_url=PROXY_TEST_URL, timeout=PROXY_TEST_TIMEOUT):
    result={'proxy_str':list(proxy_dict.values())[0],'status':'Неизвестно','origin_ip':None,'error':None}
    try:
        start_time=time.time(); resp=requests.get(target_url,proxies=proxy_dict,timeout=timeout,verify=True); latency=time.time()-start_time; resp.raise_for_status()
        try: data=resp.json(); result['origin_ip']=data.get('origin'); result['status']='Работает'; result['latency']=round(latency,2); logging.info(f"Прокси {result['proxy_str']} OK. IP: {result['origin_ip']}. Задержка: {result['latency']:.2f}с")
        except(json.JSONDecodeError,KeyError): result['status']='Ошибка ответа'; result['error']=f"Нет IP ({resp.status_code})"; logging.warning(f"Прокси {result['proxy_str']}: {result['error']}")
    except requests.exceptions.Timeout: result['status']='Таймаут'; result['error']=f"Таймаут({timeout}с)"; logging.warning(f"Прокси {result['proxy_str']}: {result['error']}")
    except requests.exceptions.ProxyError as e: result['status']='Ошибка прокси'; result['error']=str(e); logging.warning(f"Прокси {result['proxy_str']}: {result['error']}")
    except requests.exceptions.SSLError as e: result['status']='Ошибка SSL'; result['error']=str(e); logging.warning(f"Прокси {result['proxy_str']}: {result['error']}")
    except requests.exceptions.RequestException as e: result['status']='Ошибка соединения'; result['error']=str(e); logging.warning(f"Прокси {result['proxy_str']}: {result['error']}")
    except Exception as e: result['status']='Неизв.ошибка'; result['error']=str(e); logging.error(f"Прокси {result['proxy_str']}: Ошибка теста: {e}",exc_info=True)
    return result

def mask_proxy_string(proxy_url_str):
    try:
        parsed=urlparse(proxy_url_str);
        if parsed.password: netloc_parts=parsed.netloc.split('@'); user_pass=netloc_parts[0].split(':'); user=user_pass[0]; masked_netloc=f"{user}:***@{netloc_parts[1]}"; return parsed._replace(netloc=masked_netloc).geturl()
        else: return proxy_url_str
    except Exception: return proxy_url_str

# --- Управление процессами парсинга ---
def capture_parser_output(process, task_id, competitor_name):
    parser_fin=False
    try:
        logging.info(f"[T:{task_id[:6]}] Поток '{competitor_name}'(PID:{process.pid}) запущен.")
        for line in iter(process.stdout.readline, ''):
            if not line: continue
            lt = line.strip()
            try:
                if lt:
                    if lt.startswith("PROGRESS_UPDATE::"):
                        try:
                            p_data={}; parts=lt.split('::')[1:]
                            for part in parts: k,v=part.split('=',1); p_data[k.strip()]=v.strip()
                            p_task_id=p_data.get('task_id'); p_curr=int(p_data.get('current',0)); p_total=int(p_data.get('total',0))
                            if p_task_id==task_id: perc=round((p_curr/p_total)*100,1) if p_total>0 else 0; socketio.emit('parsing_progress',{'task_id':task_id,'current':p_curr,'total':p_total,'percentage':perc,'name':competitor_name})
                        except Exception as e: logging.error(f"[T:{task_id[:6]}] Ошибка прогресса: '{lt}' - {e}")
                    elif lt.startswith(f"PAUSED::{task_id}::"):
                        if competitor_name in parsing_processes: parsing_processes[competitor_name]['paused'] = True
                        socketio.emit('refresh_stats',{})
                        logging.info(f"[T:{task_id[:6]}][P] {lt}")
                        socketio.emit('parsing_log',{'task_id':task_id,'log':lt})
                    else:
                        logging.info(f"[T:{task_id[:6]}][P] {lt}"); socketio.emit('parsing_log',{'task_id':task_id,'log':lt})
            except Exception as e: logging.error(f"[T:{task_id[:6]}] Ошибка обработки строки: {lt} - {e}")
        logging.info(f"[T:{task_id[:6]}] Stdout закрыт, ждем..."); process.wait(); parser_fin=True; rc=process.returncode
        logging.info(f"[T:{task_id[:6]}] Процесс завершен: {rc}")
        if competitor_name in parsing_processes: parsing_processes[competitor_name]['paused'] = False
        comps=load_competitors();
        if competitor_name in comps: comps[competitor_name]['last_check']=datetime.now(timezone.utc).isoformat(); save_competitors(comps); logging.info(f"Обновлен last_check '{competitor_name}'.")
        socketio.emit('stats_data_updated', {'competitor': competitor_name})
        socketio.emit('parsing_finished',{'task_id':task_id,'return_code':rc}); socketio.emit('refresh_stats',{})
    except Exception as e:
        logging.error(f"[T:{task_id[:6]}] Ошибка потока: {e}",exc_info=True)
        if process and process.poll() is None:
             try: process.terminate(); time.sleep(0.5); process.kill(); logging.warning(f"[T:{task_id[:6]}] Процесс убит.")
             except Exception as te: logging.error(f"[T:{task_id[:6]}] Не убит: {te}")
    finally:
        logging.info(f"[T:{task_id[:6]}] Поток завершен.")
        if competitor_name in parsing_processes and parsing_processes[competitor_name]['task_id']==task_id:
            pff = os.path.join(FLAGS_DIR, f"pause_{task_id}.flag")
            if os.path.exists(pff):
                 try: os.remove(pff); logging.info(f"Удален флаг паузы {task_id}")
                 except OSError as e: logging.error(f"Не удален флаг паузы {pff}: {e}")
            del parsing_processes[competitor_name]; logging.info(f"Запись о процессе '{competitor_name}'(T:{task_id[:6]}) удалена.")

# --- Маршруты Flask ---
@app.route('/')
@login_required
def index():
    try: stats=get_competitor_stats()
    except Exception as e: logging.error(f"Ошибка get_stats: {e}",exc_info=True); flash("Ошибка стат-ки.","danger"); stats=[]
    return render_template('index.html',stats=stats)

@app.route('/login', methods=['GET','POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('index'))
    if request.method=='POST':
        un=request.form.get('username'); pw=request.form.get('password')
        if not un or not pw: flash('Нужен логин/пароль','warning'); return render_template('login.html')
        users=load_users(); found=False
        for uid,udata in users.items():
            if udata.get('username')==un:
                found=True
                if check_password_hash(udata.get('password_hash',''),pw):
                    user=load_user(uid);
                    if user: login_user(user,remember=True); logging.info(f"Вход: '{un}'."); np=request.args.get('next'); return redirect(np or url_for('index'))
                    else: flash('Ошибка данных.','danger'); logging.error(f"Не создан User ID {uid}.")
                else: flash('Неверный пароль','danger'); logging.warning(f"Пароль для '{un}' неверный.")
                break
        if not found: flash('Нет такого юзера','danger'); logging.warning(f"'{un}' не найден.")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout(): logging.info(f"Выход: '{current_user.username}'."); logout_user(); flash('Вы вышли.','success'); return redirect(url_for('login'))

@app.route('/competitors')
@login_required
@permission_required('competitors')
def competitors():
    try: cdata=load_competitors()
    except Exception as e: logging.error(f"Ошибка load_competitors: {e}",exc_info=True); flash("Ошибка.","danger"); cdata={}
    return render_template('competitors.html',competitors=cdata)

@app.route('/add_competitor', methods=['POST'])
@login_required
@permission_required('add_competitor')
def add_competitor():
    try:
        n=request.form.get('name','').strip(); s_raw=request.form.get('sitemap_urls','').strip(); s_urls=[u.strip() for u in s_raw.splitlines() if u.strip()]
        vst=request.form.get('views_selector_type','xpath'); dst=request.form.get('date_selector_type','xpath')
        vs_raw=request.form.get('views_selectors','').strip(); ds_raw=request.form.get('date_selectors','').strip()
        vs=[s.strip() for s in vs_raw.splitlines() if s.strip()]; ds=[s.strip() for s in ds_raw.splitlines() if s.strip()]
        use_proxy = request.form.get('use_proxy') == 'on'
        if not n or not s_urls or not vs or not ds: flash('Все поля нужны','danger'); return redirect(url_for('competitors'))
        inv_urls=[u for u in s_urls if not u.startswith(('http:','https:'))]
        if inv_urls: flash(f'Неверный URL карты: {", ".join(inv_urls)}','danger'); return redirect(url_for('competitors'))
        comps=load_competitors();
        if n in comps: flash(f'"{n}" занято','danger'); return redirect(url_for('competitors'))
        comps[n]={'source_type':'sitemap','sitemap_urls':s_urls,'views_selector_type':vst,'views_selectors':vs,'date_selector_type':dst,'date_selectors':ds,'use_proxy':use_proxy,'last_check':None,'last_full_parse_stats':None,'processed_urls':[]}
        save_competitors(comps); logging.info(f"Добавлен '{n}' ({current_user.username})"); flash(f'"{n}" добавлен','success')
    except Exception as e: logging.error(f"Ошибка добавления: {e}",exc_info=True); flash(f'Ошибка: {e}','danger')
    return redirect(url_for('competitors'))

@app.route('/edit_competitor/<name>', methods=['GET','POST'])
@login_required
@permission_required('edit_competitor')
def edit_competitor(name):
    comps=load_competitors();
    if name not in comps: flash(f'"{name}" не найден','danger'); return redirect(url_for('competitors'))
    cfg=comps[name]
    if request.method=='POST':
        try:
            s_raw=request.form.get('sitemap_urls','').strip(); s_urls=[u.strip() for u in s_raw.splitlines() if u.strip()]
            vst=request.form.get('views_selector_type','xpath'); dst=request.form.get('date_selector_type','xpath')
            vs_raw=request.form.get('views_selectors','').strip(); ds_raw=request.form.get('date_selectors','').strip()
            vs=[s.strip() for s in vs_raw.splitlines() if s.strip()]; ds=[s.strip() for s in ds_raw.splitlines() if s.strip()]
            use_proxy = request.form.get('use_proxy') == 'on'
            if not s_urls or not vs or not ds: flash('Все поля нужны','danger'); return render_template('edit_competitor.html',name=name,config=cfg,sitemap_urls_text=s_raw, views_selectors_text=vs_raw, date_selectors_text=ds_raw)
            inv_urls=[u for u in s_urls if not u.startswith(('http:','https:'))]
            if inv_urls: flash(f'Неверный URL карты: {", ".join(inv_urls)}','danger'); return render_template('edit_competitor.html',name=name,config=cfg,sitemap_urls_text=s_raw, views_selectors_text=vs_raw, date_selectors_text=ds_raw)
            comps[name].update({'sitemap_urls':s_urls,'views_selector_type':vst,'views_selectors':vs,'date_selector_type':dst,'date_selectors':ds, 'use_proxy':use_proxy}); save_competitors(comps)
            logging.info(f"Обновлен '{name}' ({current_user.username})"); flash(f'"{name}" обновлен','success'); return redirect(url_for('competitors'))
        except Exception as e:
            logging.error(f"Ошибка ред.'{name}': {e}",exc_info=True); flash(f'Ошибка: {e}','danger')
            cfg.update({'sitemap_urls':request.form.getlist('sitemap_urls'),'views_selector_type':request.form.get('views_selector_type'),'views_selectors':request.form.get('views_selectors','').strip().splitlines(),'date_selector_type':request.form.get('date_selector_type'),'date_selectors':request.form.get('date_selectors','').strip().splitlines(), 'use_proxy': request.form.get('use_proxy') == 'on'})
            return render_template('edit_competitor.html',name=name,config=cfg,sitemap_urls_text=request.form.get('sitemap_urls',''),views_selectors_text=request.form.get('views_selectors',''),date_selectors_text=request.form.get('date_selectors',''))
    s_text="\n".join(cfg.get('sitemap_urls',[])); vs_text="\n".join(cfg.get('views_selectors',[])); ds_text="\n".join(cfg.get('date_selectors',[]))
    return render_template('edit_competitor.html',name=name,config=cfg,sitemap_urls_text=s_text,views_selectors_text=vs_text,date_selectors_text=ds_text)

@app.route('/delete_competitor/<name>', methods=['POST'])
@login_required
@permission_required('delete_competitor')
def delete_competitor(name):
    comps=load_competitors();
    if name in comps:
        try:
             if name in parsing_processes: p_info=parsing_processes[name]; proc=p_info.get('process');
             if proc and proc.poll() is None: logging.warning(f"Стоп '{name}'..."); proc.terminate(); proc.wait(timeout=2); logging.info(f"'{name}' остановлен.")
             if name in parsing_processes: del parsing_processes[name]
             del comps[name]; save_competitors(comps); logging.info(f"Удален '{name}' ({current_user.username})"); flash(f'"{name}" удален','success')
        except Exception as e: logging.error(f"Ошибка удаления '{name}': {e}",exc_info=True); flash(f'Ошибка: {e}','danger')
    else: flash(f'"{name}" не найден','danger')
    return redirect(url_for('index'))

@app.route('/test_selector', methods=['POST'])
@login_required
@permission_required('test_selector_route')
def test_selector_route():
    url=request.form.get('url'); sel=request.form.get('selector'); st=request.form.get('selector_type','xpath')
    if not url or not sel: return jsonify({'success':False,'error':'Нужны URL/селектор'})
    if not url.startswith(('http:','https')): return jsonify({'success':False,'error':'Неверный URL'})
    return jsonify(test_selectors(url,sel,st))

@app.route('/test_sitemap', methods=['POST'])
@login_required
@permission_required('test_sitemap_route')
def test_sitemap_route():
    s_url=request.form.get('sitemap_url');
    if not s_url: return jsonify({'success':False,'error':'Нужен URL'})
    if not s_url.startswith(('http:','https:')): return jsonify({'success':False,'error':'Неверный URL'})
    return jsonify(test_sitemap(s_url))

# --- Запуск и Управление Парсингом ---
@app.route('/manual_parse', methods=['POST'])
@login_required
@permission_required('manual_parse')
def manual_parse():
    name = request.form.get('name'); full = request.form.get('full_parse','0') == '1'
    if not name: return jsonify({'success':False,'error':'Нужно имя'})
    comps = load_competitors();
    if name not in comps: return jsonify({'success':False,'error':f'"{name}" не найден'})
    if name in parsing_processes:
        p_inf = parsing_processes[name]; p_al = p_inf.get('process') and p_inf['process'].poll() is None; t_al = p_inf.get('output_thread') and p_inf['output_thread'].is_alive()
        if p_al or t_al: logging.warning(f"'{name}' парсится."); return jsonify({'success':False,'error':f'"{name}" парсится (T:{p_inf.get("task_id","?")[:6]})'})
        else: del parsing_processes[name]
    try:
        scr_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),PARSER_SCRIPT);
        if not os.path.exists(scr_path): return jsonify({'success':False,'error':f'Не найден {PARSER_SCRIPT}'})
        t_id = str(uuid.uuid4())
        cmd = [sys.executable, scr_path, '--competitor', name, '--task-id', t_id]
        log_m = f"Инкр. '{name}' (T:{t_id[:6]})."
        if full: cmd.append('--full'); log_m = f"ПОЛН. '{name}' (T:{t_id[:6]})."
        logging.info(log_m)
        os.makedirs(FLAGS_DIR, exist_ok=True)
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=1, universal_newlines=True, encoding='utf-8', errors='replace')
        logging.info(f"Процесс PID: {proc.pid}")
        out_thr = threading.Thread(target=capture_parser_output, args=(proc,t_id,name), daemon=True); out_thr.start()
        parsing_processes[name] = {'process':proc,'output_thread':out_thr,'task_id':t_id,'start_time':datetime.now().strftime(DATE_FORMAT),'is_full':full, 'paused': False}
        socketio.emit('refresh_stats',{}); return jsonify({'success':True,'message':f'Запущен "{name}"','task_id':t_id,'is_full':full})
    except Exception as e: logging.error(f"Ошибка запуска '{name}': {e}",exc_info=True); return jsonify({'success':False,'error':f'Ошибка: {str(e)}'})

# --- Пауза/Возобновление Парсинга ---
@app.route('/pause_parse/<task_id>', methods=['POST'])
@login_required
@permission_required('pause_parse')
def pause_parse(task_id):
    competitor_name = None
    for name, info in parsing_processes.items():
        if info.get('task_id') == task_id: competitor_name = name; break
    if not competitor_name or competitor_name not in parsing_processes: return jsonify({'success': False, 'error': 'Процесс не найден.'})
    p_info = parsing_processes[competitor_name]; process = p_info.get('process')
    if not process or process.poll() is not None: return jsonify({'success': False, 'error': 'Процесс завершен.'})
    pause_flag_file = os.path.join(FLAGS_DIR, f"pause_{task_id}.flag")
    try:
        with open(pause_flag_file, 'w') as f: f.write(datetime.now().isoformat())
        p_info['paused'] = True; logging.info(f"Пауза для '{competitor_name}' (T:{task_id[:6]}) ({current_user.username}).")
        socketio.emit('refresh_stats',{}); flash(f'Парсинг "{competitor_name}" поставлен на паузу.', 'info')
        return jsonify({'success': True, 'message': f'"{competitor_name}" на паузе.'})
    except Exception as e: logging.error(f"Ошибка паузы {task_id}: {e}", exc_info=True); return jsonify({'success': False, 'error': f'Ошибка: {e}'})

@app.route('/resume_parse/<task_id>', methods=['POST'])
@login_required
@permission_required('resume_parse')
def resume_parse(task_id):
    competitor_name = None
    for name, info in parsing_processes.items():
        if info.get('task_id') == task_id: competitor_name = name; break
    if not competitor_name or competitor_name not in parsing_processes: return jsonify({'success': False, 'error': 'Процесс не найден.'})
    p_info = parsing_processes[competitor_name]; pause_flag_file = os.path.join(FLAGS_DIR, f"pause_{task_id}.flag")
    if os.path.exists(pause_flag_file):
        try:
            os.remove(pause_flag_file); p_info['paused'] = False; logging.info(f"Снята пауза '{competitor_name}' (T:{task_id[:6]}) ({current_user.username}).")
            socketio.emit('refresh_stats',{}); flash(f'Парсинг "{competitor_name}" возобновлен.', 'success')
            return jsonify({'success': True, 'message': f'"{competitor_name}" возобновлен.'})
        except Exception as e:
            logging.error(f"Ошибка снятия паузы {task_id}: {e}", exc_info=True); p_info['paused'] = False; socketio.emit('refresh_stats',{})
            return jsonify({'success': False, 'error': f'Ошибка: {e}'})
    else: p_info['paused'] = False; socketio.emit('refresh_stats',{}); return jsonify({'success': True, 'message': 'Уже активен.'})

# --- Статистика и Данные ---
@app.route('/statistics')
@login_required
@permission_required('statistics')
def statistics():
    try:
        selected_competitors = request.args.getlist('competitor')
        start_date_str = request.args.get('start_date')
        end_date_str = request.args.get('end_date')
        search_term = request.args.get('search_term', '').strip()

        logging.info(f"Запрос статистики: Конкуренты={selected_competitors}, ДатаС={start_date_str}, ДатаПо={end_date_str}, Поиск={search_term}")

        data = get_all_data()
        competitors_list = list(load_competitors().keys())

        render_opts = { 'competitors': competitors_list, 'selected_competitors': selected_competitors, 'start_date': start_date_str, 'end_date': end_date_str, 'search_term': search_term, 'error': None, 'total_articles': 0, 'competitor_stats': [], 'top_articles': [], 'all_articles': [], 'views_chart': None, 'competitor_chart': None }

        if data.empty: logging.warning("Статистика: DataFrame пуст после get_all_data()."); render_opts['error'] = "Данные для анализа не найдены."; return render_template('statistics.html', **render_opts)

        try:
            data['check_date'] = pd.to_datetime(data['check_date'], errors='coerce')
            data['published_page_date'] = pd.to_datetime(data['published_page_date'], errors='coerce')
            if 'views_num' not in data.columns: data['views_num'] = 0
            data['views_num'] = pd.to_numeric(data['views_num'], errors='coerce').fillna(0).astype(int)
            for col in ['title', 'url', 'competitor']:
                 if col in data.columns: data[col] = data[col].fillna('(нет данных)')
                 else: data[col] = '(нет данных)'
        except Exception as e: logging.error(f"Ошибка преобразования типов данных в статистике: {e}", exc_info=True); render_opts['error'] = f"Внутренняя ошибка при обработке данных: {e}"; return render_template('statistics.html', **render_opts)

        fdata = data.copy()

        if selected_competitors and 'all' not in selected_competitors: fdata = fdata[fdata['competitor'].isin(selected_competitors)]
        try:
            if start_date_str: start_date = pd.to_datetime(start_date_str, errors='coerce');
            if pd.notna(start_date): fdata = fdata[fdata['check_date'] >= start_date]
            else: flash("Неверный формат начальной даты.", "warning") if start_date_str else None
            if end_date_str: end_date = pd.to_datetime(end_date_str, errors='coerce');
            if pd.notna(end_date): fdata = fdata[fdata['check_date'] < end_date + timedelta(days=1)]
            else: flash("Неверный формат конечной даты.", "warning") if end_date_str else None
        except Exception as e: logging.warning(f"Ошибка фильтрации по дате: {e}"); flash("Ошибка при фильтрации по дате.", "warning")

        if search_term:
            try: fdata = fdata[fdata['title'].str.contains(search_term,case=False,na=False)|fdata['url'].str.contains(search_term,case=False,na=False)]
            except Exception as e: logging.warning(f"Ошибка поиска '{search_term}': {e}"); flash("Ошибка при поиске.", "warning")

        total_articles = len(fdata)
        render_opts['total_articles'] = total_articles

        if fdata.empty: logging.warning("Статистика: DataFrame пуст ПОСЛЕ фильтрации."); render_opts['error'] = "По заданным фильтрам данные не найдены."; return render_template('statistics.html', **render_opts)

        try:
            if 'published_page_date' in fdata.columns:
                now_naive = datetime.now(timezone.utc).replace(tzinfo=None);
                pub_n = fdata['published_page_date'].dt.tz_localize(None) if fdata['published_page_date'].dt.tz is not None else fdata['published_page_date']
                valid_dates_mask = pub_n.notna()
                if valid_dates_mask.any():
                    delt=(now_naive-pub_n[valid_dates_mask]); days=(delt.dt.total_seconds()/86400).apply(lambda x:max(x,0.1));
                    fdata.loc[valid_dates_mask, 'avg_daily_views'] = (fdata.loc[valid_dates_mask, 'views_num'] / days).round(1)
            if 'avg_daily_views' not in fdata.columns: fdata['avg_daily_views'] = 0.0
            else: fdata['avg_daily_views'] = fdata['avg_daily_views'].fillna(0.0) # Исправлено fillna
        except Exception as e: logging.error(f"Ошибка расчета avg_daily_views: {e}", exc_info=True); fdata['avg_daily_views'] = 0.0; flash("Ошибка расч. ср. просмотров.", "warning")

        try:
            if 'competitor' in fdata.columns: cstatsf = fdata['competitor'].value_counts().reset_index(); cstatsf.columns = ['competitor', 'count']; render_opts['competitor_stats'] = cstatsf.to_dict('records')
            else: render_opts['competitor_stats'] = []
        except Exception as e: logging.error(f"Ошибка value_counts: {e}", exc_info=True); render_opts['competitor_stats'] = []

        try:
            if 'views_num' in fdata.columns:
                topa = fdata.nlargest(10, 'views_num').copy(); topa['formatted_check_date']=topa['check_date'].apply(format_date_short); topa['formatted_published']=topa['published_page_date'].apply(format_datetime); render_opts['top_articles'] = topa.to_dict('records')
            else: render_opts['top_articles'] = []
        except Exception as e: logging.error(f"Ошибка топа статей: {e}", exc_info=True); render_opts['top_articles'] = []

        try:
             cols=['title','url','competitor','views_num','avg_daily_views','published_page_date','check_date']; existc=[c for c in cols if c in fdata.columns]; dispdf=fdata[existc].copy()
             dispdf['formatted_published']=dispdf['published_page_date'].apply(format_datetime); dispdf['formatted_check_date']=dispdf['check_date'].apply(format_date_short)
             fill_vals={'title':'(N/A)','url':'#','competitor':'?','views_num':0,'avg_daily_views':0.0};
             dispdf_filled = dispdf.fillna(value=fill_vals) # Исправлено fillna
             render_opts['all_articles'] = dispdf_filled.to_dict('records')
        except Exception as e: logging.error(f"Ошибка подготовки списка статей: {e}", exc_info=True); render_opts['all_articles'] = []

        try:
            fdata_chart_v = fdata.dropna(subset=['check_date', 'views_num', 'competitor'])
            if not fdata_chart_v.empty:
                fdata_chart_v['check_date_only'] = fdata_chart_v['check_date'].dt.date;
                vbd = fdata_chart_v.groupby(['check_date_only', 'competitor'], observed=False)['views_num'].mean().reset_index()
                if not vbd.empty: figv=px.line(vbd,x='check_date_only',y='views_num',color='competitor',title='Средние просмотры',markers=True,labels={'check_date_only':'Дата','views_num':'Ср. просмотры'}); render_opts['views_chart']=json.dumps(figv,cls=plotly.utils.PlotlyJSONEncoder)
            if render_opts['competitor_stats']: figc=px.pie(render_opts['competitor_stats'],values='count',names='competitor',title='Статьи(выборка)'); render_opts['competitor_chart']=json.dumps(figc,cls=plotly.utils.PlotlyJSONEncoder)
        except Exception as e: logging.error(f"Ошибка генерации графиков: {e}", exc_info=True); flash("Ошибка графиков.", "warning")

        return render_template('statistics.html', **render_opts)

    except Exception as e: logging.error(f"Крит.ошибка стат-ки: {e}",exc_info=True); flash("Ошибка загрузки.","danger"); clist=list(load_competitors().keys()); return render_template('statistics.html',error="Внутр.ошибка.",competitors=clist)

@app.route('/data')
@login_required
@permission_required('get_data')
def get_data():
    try:
        data=get_all_data();
        if data.empty: return jsonify({"data":[]})
        sc=request.args.get('competitor','all'); sd=request.args.get('start_date'); ed=request.args.get('end_date'); srch=request.args.get('search_term','').strip()
        data['check_date']=pd.to_datetime(data['check_date'],errors='coerce'); data['published_page_date']=pd.to_datetime(data['published_page_date'],errors='coerce')
        fdata=data.copy();
        if sc and sc!='all': fdata=fdata[fdata['competitor']==sc]
        try:
            if sd: fdata=fdata[fdata['check_date']>=pd.to_datetime(sd)]
            if ed: fdata=fdata[fdata['check_date']<=pd.to_datetime(ed)+timedelta(days=1)]
        except ValueError: pass
        if srch: fdata=fdata[fdata['title'].str.contains(srch,case=False,na=False)|fdata['url'].str.contains(srch,case=False,na=False)]
        if 'published_page_date' in fdata.columns and not fdata.empty:
             now_n=datetime.now(timezone.utc).replace(tzinfo=None);
             pub_n = fdata['published_page_date'].dt.tz_localize(None) if fdata['published_page_date'].dt.tz is not None else fdata['published_page_date']
             valid_dates_mask = pub_n.notna()
             if valid_dates_mask.any():
                  delt=(now_n-pub_n[valid_dates_mask]); days=(delt.dt.total_seconds()/86400).apply(lambda x:max(x,0.1));
                  fdata.loc[valid_dates_mask, 'avg_daily_views'] = (fdata.loc[valid_dates_mask, 'views_num'] / days).round(1)
             if 'avg_daily_views' not in fdata.columns: fdata['avg_daily_views'] = 0.0
             else: fdata['avg_daily_views'] = fdata['avg_daily_views'].fillna(0.0) # Исправлено
        else: fdata['avg_daily_views']=0.0

        fill_values = {'title':'(N/A)','views_num':0};
        if 'avg_daily_views' in fdata.columns: fill_values['avg_daily_views'] = 0.0
        fdata_filled = fdata.fillna(value=fill_values) # Исправлено

        fdata_filled['check_date_str']=fdata_filled['check_date'].apply(format_date_short);
        fdata_filled['published_page_str']=fdata_filled['published_page_date'].apply(format_datetime)
        output_cols = ['title','url','competitor','views_num','avg_daily_views','published_page_str','check_date_str']
        existing_output_cols = [col for col in output_cols if col in fdata_filled.columns]
        outd=fdata_filled[existing_output_cols].to_dict('records')
        return jsonify({"data":outd})
    except Exception as e: logging.error(f"Ошибка API /data: {e}",exc_info=True); return jsonify({"error":"Внутр.ошибка","data":[]}),500

@app.route('/competitors_api')
@login_required
@permission_required('competitors_api')
def get_competitors():
    try: return jsonify(list(load_competitors().keys()))
    except Exception as e: logging.error(f"Ошибка API /competitors_api: {e}",exc_info=True); return jsonify({"error":"Ошибка"}),500

@app.route('/refresh_stats')
@login_required
@permission_required('refresh_stats_route')
def refresh_stats_route():
    try: return jsonify({'success':True,'stats':get_competitor_stats()})
    except Exception as e: logging.error(f"Ошибка API /refresh_stats: {e}",exc_info=True); return jsonify({'success':False,'error':'Ошибка'})

# --- Маршруты Управления пользователями ---
@app.route('/users')
@login_required
@permission_required('users')
def users():
    udata=load_users(); ulist=[]
    for uid,uinfo in udata.items():
        uobj=load_user(uid);
        if uobj: ulist.append({'id':uid,'username':uinfo.get('username','N/A'),'roles':uobj.roles})
        else: logging.warning(f"Не загружен User ID {uid} стр.users.")
    return render_template('users.html',users=ulist,available_roles=list(ROLES_PERMISSIONS.keys()),admin_username=ADMIN_USERNAME)

@app.route('/add_user', methods=['POST'])
@login_required
@permission_required('add_user')
def add_user():
    un=request.form.get('username','').strip(); pw=request.form.get('password'); pwc=request.form.get('password_confirm'); sroles=request.form.getlist('roles')
    if not un or not pw: flash('Нужен логин/пароль.','danger'); return redirect(url_for('users'))
    if pw!=pwc: flash('Пароли не совпадают.','danger'); return redirect(url_for('users'))
    if len(pw)<6: flash('Пароль > 5 симв.','danger'); return redirect(url_for('users'))
    vroles=[r for r in sroles if r in ROLES_PERMISSIONS];
    if not vroles: vroles=[DEFAULT_ROLE]; flash(f'Назначена роль: {DEFAULT_ROLE}','info')
    udata=load_users();
    if any(u.get('username')==un for u in udata.values()): flash(f'"{un}" занято.','danger'); return redirect(url_for('users'))
    try:
        current_ids = [int(k) for k in udata.keys() if k.isdigit()]; new_id=str(max(current_ids)+1 if current_ids else 1)
        udata[new_id]={'username':un,'password_hash':generate_password_hash(pw),'roles':vroles}
        save_users(udata); logging.info(f"Добавлен '{un}' роли: {vroles} ({current_user.username})."); flash(f'"{un}" добавлен.','success')
    except Exception as e: logging.error(f"Ошибка добавления '{un}': {e}",exc_info=True); flash(f'Ошибка: {e}','danger')
    return redirect(url_for('users'))

@app.route('/edit_user/<user_id>', methods=['GET','POST'])
@login_required
@permission_required('edit_user')
def edit_user(user_id):
    udata=load_users(); uinfo=udata.get(user_id);
    if not uinfo: flash(f"ID {user_id} не найден.","danger"); return redirect(url_for('users'))
    un=uinfo.get('username','N/A')
    if un==ADMIN_USERNAME: flash(f"'{ADMIN_USERNAME}' нельзя ред.","warning"); return redirect(url_for('users'))
    if request.method=='POST':
        sroles=request.form.getlist('roles'); vroles=[r for r in sroles if r in ROLES_PERMISSIONS]
        if not vroles: vroles=[DEFAULT_ROLE]; flash(f'Назначена роль: {DEFAULT_ROLE}.','warning')
        try:
            udata[user_id]['roles']=vroles; save_users(udata); logging.info(f"Роли для '{un}'(ID:{user_id}) изменены: {vroles} ({current_user.username}).")
            flash(f'Роли "{un}" обновлены.','success'); return redirect(url_for('users'))
        except Exception as e: logging.error(f"Ошибка обновления '{un}': {e}",exc_info=True); flash(f'Ошибка: {e}','danger')
        return render_template('edit_user.html',user_id=user_id,username=un,user_roles=vroles,available_roles=list(ROLES_PERMISSIONS.keys()))
    uroles=uinfo.get('roles',[DEFAULT_ROLE]); return render_template('edit_user.html',user_id=user_id,username=un,user_roles=uroles,available_roles=list(ROLES_PERMISSIONS.keys()))

@app.route('/delete_user/<user_id>', methods=['POST'])
@login_required
@permission_required('delete_user')
def delete_user(user_id):
    udata=load_users(); udel=udata.get(user_id);
    if not udel: flash(f'ID {user_id} не найден.','danger'); return redirect(url_for('users'))
    uname_del=udel.get('username');
    if user_id==current_user.id: flash('Себя удалить нельзя.','danger'); return redirect(url_for('users'))
    if uname_del==ADMIN_USERNAME: flash(f'"{ADMIN_USERNAME}" удалить нельзя.','danger'); return redirect(url_for('users'))
    try:
        del udata[user_id]; save_users(udata); logging.info(f"Удален '{uname_del}'(ID:{user_id}) ({current_user.username}).")
        flash(f'"{uname_del}" удален.','success')
    except Exception as e: logging.error(f"Ошибка удаления ID {user_id}: {e}",exc_info=True); flash(f'Ошибка: {e}','danger')
    return redirect(url_for('users'))

@app.route('/change_password', methods=['GET','POST'])
@login_required
def change_password():
    if request.method=='POST':
        cp=request.form.get('current_password'); np=request.form.get('new_password'); npc=request.form.get('new_password_confirm')
        if not cp or not np or not npc: flash('Все поля нужны.','danger'); return redirect(url_for('change_password'))
        if np!=npc: flash('Пароли не совпадают.','danger'); return redirect(url_for('change_password'))
        if len(np)<6: flash('Пароль > 5 симв.','danger'); return redirect(url_for('change_password'))
        if check_password_hash(current_user.password_hash,cp):
            try:
                 udata=load_users();
                 if current_user.id in udata:
                     udata[current_user.id]['password_hash']=generate_password_hash(np); save_users(udata)
                     current_user.password_hash=udata[current_user.id]['password_hash']
                     logging.info(f"'{current_user.username}' сменил пароль."); flash('Пароль изменен.','success'); return redirect(url_for('index'))
                 else: flash('Ошибка: юзер не найден.','danger'); logging.error(f"ID {current_user.id} не найден при смене.")
            except Exception as e: logging.error(f"Ошибка смены '{current_user.username}': {e}",exc_info=True); flash(f'Ошибка: {e}','danger')
        else: flash('Текущий пароль неверен.','danger'); logging.warning(f"Неверный тек. пароль для '{current_user.username}'.")
    return render_template('change_password.html')

# --- Маршрут Тестирования Прокси ---
@app.route('/proxies')
@login_required
@permission_required('proxies')
def proxies_test_page():
    initial_results = []
    for proxy_dict in PROXIES:
         proxy_str = proxy_dict.get('original_string', list(proxy_dict.values())[0])
         initial_results.append({'proxy_str': proxy_str, 'proxy_masked': mask_proxy_string(proxy_str),'status': 'Не проверено', 'origin_ip': '-', 'latency': '-', 'error': '-'})
    return render_template('proxies.html', proxy_results=initial_results, proxy_file=PROXY_FILE, proxy_count=len(PROXIES), PROXY_TEST_URL=PROXY_TEST_URL, PROXY_TEST_TIMEOUT=PROXY_TEST_TIMEOUT)

# --- SocketIO обработчики ---
@socketio.on('connect')
def socket_connect(auth=None):
    if not current_user.is_authenticated or not current_user.can('connect'): logging.warning(f"SocketIO: нет прав 'connect' ({current_user.username if current_user.is_authenticated else 'Guest'})"); return False
    logging.info(f"SocketIO: {request.sid} подключен ({current_user.username}, {current_user.roles})"); emit('stats_update', {'stats': get_competitor_stats()})

@socketio.on('disconnect')
def socket_disconnect(): logging.info(f"SocketIO: {request.sid} отключен")

@socketio.on('get_parsing_status')
def socket_get_parsing_status(data):
    if not current_user.is_authenticated or not current_user.can('get_parsing_status'): return
    name=data.get('name'); logging.debug(f"SocketIO: get_parsing_status '{name}' от {request.sid}")
    if name in parsing_processes: pinf=parsing_processes[name]; palive=pinf.get('process') and pinf['process'].poll() is None; talive=pinf.get('output_thread') and pinf['output_thread'].is_alive(); emit('parsing_status_update',{'name':name,'is_running':palive or talive,'task_id':pinf.get('task_id'),'start_time':pinf.get('start_time'),'is_full':pinf.get('is_full',False), 'is_paused': pinf.get('paused', False)})
    else: emit('parsing_status_update',{'name':name,'is_running':False, 'is_paused': False})

@socketio.on('get_stats')
def socket_get_stats():
    if not current_user.is_authenticated or not current_user.can('get_stats'): return
    logging.debug(f"SocketIO: get_stats от {request.sid}")
    try: emit('stats_update', {'stats': get_competitor_stats()})
    except Exception as e: logging.error(f"SocketIO: Ошибка get_stats: {e}",exc_info=True); emit('error_message', {'message':'Ошибка стат-ки.'})

@socketio.on('start_proxy_test')
def handle_start_proxy_test():
    if not current_user.is_authenticated or not current_user.can('start_proxy_test'): logging.warning(f"Попытка теста прокси без прав: {current_user.username}"); emit('proxy_test_error', {'message': 'Нет прав.'}); return
    if not PROXIES: logging.warning("Запрос теста прокси, но список пуст."); emit('proxy_test_finished', {'message': 'Список прокси пуст.'}); return
    sid = request.sid; logging.info(f"Запрос теста прокси от {current_user.username} ({sid}).")
    def run_single_test(proxy_dict, client_sid):
        result = test_proxy(proxy_dict)
        result['original_string'] = proxy_dict.get('original_string', list(proxy_dict.values())[0])
        result['proxy_masked'] = mask_proxy_string(result['original_string']);
        with app.app_context(): emit('proxy_test_result', result, namespace='/', to=client_sid)
        socketio.sleep(0.05)
    def run_all_tests(client_sid):
        logging.info(f"Начало фонового теста {len(PROXIES)} прокси для {client_sid}...")
        for proxy_d in PROXIES: run_single_test(proxy_d, client_sid)
        with app.app_context(): emit('proxy_test_finished', {'message': 'Тестирование завершено.'}, namespace='/', to=client_sid)
        logging.info(f"Фоновый тест прокси для {client_sid} завершен.")
    socketio.start_background_task(run_all_tests, sid)

# --- Основной запуск ---
if __name__ == '__main__':
    os.makedirs('templates', exist_ok=True); os.makedirs(DATA_FOLDER, exist_ok=True); os.makedirs(FLAGS_DIR, exist_ok=True)
    PROXIES = load_proxies_from_file()
    load_users(); load_competitors()
    use_reloader = os.environ.get('FLASK_USE_RELOADER', 'true').lower() == 'true'
    debug = os.environ.get('FLASK_DEBUG', 'true').lower() == 'true'
    port = int(os.environ.get('PORT', 5000))
    logging.info(f"Запуск Flask+SocketIO http://0.0.0.0:{port}/ D:{debug}, R:{use_reloader}, Proxies: {len(PROXIES)}")
    socketio.run(app, debug=debug, host='0.0.0.0', port=port, use_reloader=use_reloader, allow_unsafe_werkzeug=True if use_reloader else False)