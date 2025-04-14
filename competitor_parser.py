import requests
from lxml import html
import pandas as pd
from datetime import datetime, timezone
import time
import random
import os
import json
import argparse
import sys
import re
import logging
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from threading import Lock
try:
    from dateutil.parser import parse as dateutil_parse
    from dateutil.parser._parser import ParserError as DateutilParserError
except ImportError:
    dateutil_parse = None
    DateutilParserError = None
    print("WARNING: dateutil не найден. Установите: pip install python-dateutil", file=sys.stderr)

# --- ПРИНУДИТЕЛЬНАЯ КОДИРОВКА ВЫВОДА ---
try: sys.stdout.reconfigure(encoding='utf-8'); sys.stderr.reconfigure(encoding='utf-8')
except AttributeError: import io; sys.stdout=io.TextIOWrapper(sys.stdout.buffer,encoding='utf-8',errors='replace'); sys.stderr=io.TextIOWrapper(sys.stderr.buffer,encoding='utf-8',errors='replace')

# --- Константы и Настройки ---
DATA_FOLDER = 'data'; CONFIG_FILE = 'competitors.json'; PROXY_FILE = 'proxies.txt'
FLAGS_DIR = 'flags'
log_format = '%(asctime)s - %(levelname)s - %(name)s - %(message)s'
logging.basicConfig(level=logging.INFO, format=log_format, encoding='utf-8', handlers=[logging.FileHandler("parser_process.log", encoding='utf-8'), logging.StreamHandler(sys.stdout)])
logger = logging.getLogger("CompetitorParser")

USER_AGENTS = ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36','Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15','Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36']
PROXIES = []
REQUEST_TIMEOUT = 30; REQUEST_DELAY_MIN = 0.5; REQUEST_DELAY_MAX = 1.5
SITEMAP_REQUEST_DELAY = 0.5; MAX_RETRIES = 2
PAUSE_CHECK_INTERVAL = 1; CONFIG_UPDATE_FREQUENCY = 50; MAX_WORKERS = 10

# --- Загрузка прокси ---
def load_proxies_from_file(filepath=PROXY_FILE):
    proxies_list = [];
    if not os.path.exists(filepath): logger.warning(f"'{filepath}' не найден."); return proxies_list
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for ln, line in enumerate(f):
                line = line.strip();
                if not line or line.startswith('#'): continue
                parts = line.split(':')
                if len(parts)==4: ip,port,login,pw=parts; pu=f"http://{login}:{pw}@{ip}:{port}"; proxies_list.append({'http':pu,'https':pu,'original_string':line})
                else: logger.warning(f"Неверный формат {ln+1} '{filepath}': '{line}'.")
        logger.info(f"Загружено {len(proxies_list)} прокси из '{filepath}'.")
    except Exception as e: logger.error(f"Ошибка '{filepath}': {e}",exc_info=True)
    return proxies_list

# --- Утилитарные функции ---
def get_random_headers(): ua=random.choice(USER_AGENTS) if USER_AGENTS else 'Mozilla/5.0'; return {'User-Agent':ua}
def load_competitors_config():
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f: data = json.load(f)
        return data
    except FileNotFoundError: logger.error(f"'{CONFIG_FILE}' не найден."); return None
    except json.JSONDecodeError as e: logger.error(f"Ошибка JSON в '{CONFIG_FILE}': {e}"); return None
    except Exception as e: logger.error(f"Неизвестная ошибка при загрузке '{CONFIG_FILE}': {e}", exc_info=True); return None

def update_competitor_config_field(cname, fname, val):
    lockf=CONFIG_FILE+".lock"; w=0; max_w=5
    try:
        while os.path.exists(lockf) and w<max_w: time.sleep(0.1); w+=0.1
        if os.path.exists(lockf): logger.error(f"Не блок '{CONFIG_FILE}' для {fname}."); return False
        with open(lockf,'w') as lf: lf.write(f"{os.getpid()}");
        competitors=load_competitors_config();
        if competitors is None: return False
        if cname in competitors:
            competitors[cname][fname]=val
            try: f=open(CONFIG_FILE,'w',encoding='utf-8'); json.dump(competitors,f,ensure_ascii=False,indent=4); f.close(); logger.debug(f"Обновлено '{fname}' для '{cname}'."); return True
            except Exception as e: logger.error(f"Ошибка записи {fname} '{CONFIG_FILE}': {e}",exc_info=True); return False
        else: logger.warning(f"Нет '{cname}' для {fname}"); return False
    except Exception as e: logger.error(f"Ошибка блок/обн {fname} '{CONFIG_FILE}': {e}",exc_info=True); return False
    finally:
        if os.path.exists(lockf):
             try: os.remove(lockf)
             except OSError as e: logger.error(f"Не удален lock '{lockf}': {e}")

def normalize_url(url, base): u=url.strip(); p=urlparse(u); return urljoin(base,u) if not p.scheme else u

# --- Функции парсинга С РОТАЦИЕЙ ПРОКСИ ---
def make_request_with_proxy_rotation(url, headers, use_proxy, max_tries=MAX_RETRIES):
    global PROXIES
    attempts=[None];
    if use_proxy and PROXIES: apl=list(PROXIES); random.shuffle(apl); attempts=apl+[None]; logger.debug(f"Req {url}. Пр ON({len(apl)}).")
    elif use_proxy and not PROXIES: logger.warning(f"Req {url}. Пр ON, но список пуст.")
    else: logger.debug(f"Req {url}. Пр OFF.")
    for idx, cp in enumerate(attempts):
        pinf=f"proxy {list(cp.values())[0].split('@')[1]}" if cp else "direct"
        logger.debug(f"Req {url}: Поп.{idx+1}/{len(attempts)} ({pinf})")
        for try_n in range(max_tries+1):
             if try_n==max_tries and cp is not None: logger.warning(f"Попытки({max_tries}) {url} с {pinf} исчерпаны"); break
             try:
                 time.sleep(random.uniform(REQUEST_DELAY_MIN/2,REQUEST_DELAY_MAX/2) if try_n>0 else 0.05)
                 resp=requests.get(url,headers=headers,proxies=cp,timeout=REQUEST_TIMEOUT,verify=True); resp.raise_for_status()
                 logger.debug(f"OK {url} ({pinf}, поп.{try_n+1})"); return resp
             except requests.exceptions.Timeout: logger.warning(f"Поп.{try_n+1}: Таймаут {url} ({pinf})")
             except requests.exceptions.ProxyError as e: logger.warning(f"Поп.{try_n+1}: Ошибка прокси {url} ({pinf}): {e}"); break
             except requests.exceptions.RequestException as e: logger.warning(f"Поп.{try_n+1}: Ошибка сети {url} ({pinf}): {e}")
    logger.error(f"Не удалось {url} после всех попыток."); return None

def get_urls_from_sitemap(surl, use_proxy, processed=None):
    if processed is None: processed=set()
    if surl in processed: logger.debug(f"Sitemap {surl} skip."); return []
    logger.info(f"Обработка Sitemap: {surl}"); processed.add(surl)
    urls=[]; hdrs=get_random_headers(); resp=make_request_with_proxy_rotation(surl,hdrs,use_proxy,1)
    if resp:
        try:
            ct=resp.headers.get('Content-Type','').lower();
            if 'xml' not in ct: logger.warning(f"Не XML ({ct}) для Sitemap: {surl}")
            resp.encoding=resp.apparent_encoding; content=resp.text
            root=html.fromstring(content.encode(resp.encoding),parser=html.etree.XMLParser(recover=True)); ns={'sm':'http://www.sitemaps.org/schemas/sitemap/0.9'}
            s_locs=root.xpath('//sm:sitemap/sm:loc/text()',namespaces=ns) or root.xpath('//sitemap/loc/text()')
            if s_locs: logger.info(f"Index в {surl}, {len(s_locs)} карт."); [urls.extend(get_urls_from_sitemap(normalize_url(l,surl),use_proxy,processed)) for l in s_locs]
            p_locs=root.xpath('//sm:url/sm:loc/text()',namespaces=ns) or root.xpath('//url/loc/text()')
            if p_locs: norm_urls=[normalize_url(l,surl) for l in p_locs]; logger.info(f"{len(norm_urls)} URL в {surl}"); urls.extend(norm_urls)
            if not s_locs and not p_locs: logger.warning(f"Нет тегов в {surl}")
        except Exception as e: logger.error(f"Ошибка парсинга XML {surl}: {e}",exc_info=True)
    return urls

def parse_page(url, config):
    vst=config.get('views_selector_type','xpath'); dst=config.get('date_selector_type','xpath')
    vs=config.get('views_selectors',[]); ds=config.get('date_selectors',[])
    use_proxy=config.get('use_proxy',False)
    pdata={'url':url,'title':None,'views':None,'published_page':None,'parse_error':None}
    if not vs and not ds: logger.warning(f"Нет селекторов {url}"); pdata['parse_error']='missing_selectors'; return pdata
    hdrs=get_random_headers(); resp=make_request_with_proxy_rotation(url,hdrs,use_proxy)
    if not resp: pdata['parse_error']='network_error'; return pdata
    try:
        resp.encoding=resp.apparent_encoding; tree=html.fromstring(resp.text)
        tel=tree.xpath('//title/text()') or tree.xpath('//h1/text()'); pdata['title']=tel[0].strip() if tel else None
        # Просмотры
        if vs:
            vf=False
            for i,sel in enumerate(vs):
                txt = None
                try:
                    els=tree.xpath(sel) if vst=='xpath' else tree.cssselect(sel)
                    if els: f=els[0]; txt=f.text_content().strip() if hasattr(f,'text_content') else str(f).strip() if isinstance(f,str) else str(f).strip()
                    if txt: pdata['views']=txt; logger.debug(f"Views OK:{url}(#{i+1})"); vf=True; break
                    else: logger.debug(f"Views sel#{i+1}({sel}) empty {url}")
                except Exception as e: logger.warning(f"Views sel#{i+1}({sel}) err {url}: {e}"); continue
            if not vf:
                logger.warning(f"Views: Ни один из {len(vs)} не сработал {url}")
                if not pdata['parse_error']: pdata['parse_error']="views_selectors_failed"
        else: logger.warning(f"Views: Пустой список {url}"); pdata['parse_error']="views_selectors_missing" if not pdata['parse_error'] else pdata['parse_error']
        # Дата
        if ds:
            df=False
            for i,sel in enumerate(ds):
                try:
                    els=tree.xpath(sel) if dst=='xpath' else tree.cssselect(sel)
                    if els:
                        f=els[0]; dt_attr=None; tc=None;
                        if hasattr(f,'get'): dt_attr=f.get('datetime') or f.get('time') or f.get('content')
                        if hasattr(f,'text_content'): tc=f.text_content().strip()
                        elif isinstance(f,str): tc=f.strip()
                        rt=dt_attr.strip() if dt_attr else tc
                        if rt:
                            parsed_dt_iso = rt
                            try:
                                if dateutil_parse: parsed_dt=dateutil_parse(rt,dayfirst=True,fuzzy=True); parsed_dt_iso=parsed_dt.isoformat()
                            except (DateutilParserError,ValueError,OverflowError,TypeError) as date_e: logger.warning(f"Date Parse Err sel#{i+1}({sel}) '{rt}' {url}: {date_e}"); parsed_dt_iso=rt
                            except Exception as general_date_e: logger.error(f"Unexpected Date Parse Err sel#{i+1}({sel}) '{rt}' {url}: {general_date_e}",exc_info=True); parsed_dt_iso=rt
                            pdata['published_page']=parsed_dt_iso; logger.debug(f"Date OK:{url}(#{i+1}) -> {parsed_dt_iso}"); df=True; break
                        else: logger.debug(f"Date sel#{i+1}({sel}) empty {url}")
                except Exception as e: logger.warning(f"Date sel#{i+1}({sel}) err {url}: {e}"); continue
            if not df:
                 logger.warning(f"Date: Ни один из {len(ds)} не сработал {url}")
                 if not pdata['parse_error']: pdata['parse_error']="date_selectors_failed"
        else: logger.warning(f"Date: Пустой список {url}"); pdata['parse_error']="date_selectors_missing" if not pdata['parse_error'] else pdata['parse_error']
        if pdata['views'] is None and pdata['published_page'] is None and not pdata['parse_error']: pdata['parse_error'] = "parsing_failed_no_data"
        return pdata
    except html.etree.ParserError as e: logger.error(f"HTML Err {url}: {e}"); pdata['parse_error']=f"html_parse_error:{e}"; return pdata
    except Exception as e: logger.error(f"Unexpected Parse Err {url}: {e}",exc_info=True); pdata['parse_error']=f"unexpected_parse_error:{e}"; return pdata

# --- Инкрементальное сохранение данных ---
def save_incremental_data(page_data, competitor_name):
    if not page_data or not isinstance(page_data, dict): return False
    if page_data.get('views') is None and page_data.get('published_page') is None: logger.debug(f"Пропуск сохр. {page_data.get('url')}"); return False
    today=datetime.now().strftime('%Y-%m-%d'); fname=f"{competitor_name}_{today}.csv"
    fpath=os.path.join(DATA_FOLDER,fname); os.makedirs(DATA_FOLDER,exist_ok=True)
    df = pd.DataFrame([page_data])
    df['check_date'] = today; exists = os.path.exists(fpath)
    try: df.to_csv(fpath,mode='a',header=not exists,index=False,sep=';',encoding='utf-8'); logger.debug(f"Сохранена {page_data.get('url')} в {fpath}"); return True
    except Exception as e: logger.error(f"Ошибка инкр.записи {fpath}: {e}",exc_info=True); return False

# === Функция для выполнения в потоке ===
def process_url_worker(url, config, task_id, save_lock, results_lock, processed_urls_lock, processed_urls_set, counters):
    competitor_name = config.get('_competitor_name_', "unknown")
    pause_flag_file = os.path.join(FLAGS_DIR, f"pause_{task_id}.flag")
    worker_id = threading.get_ident()

    was_paused = False
    while os.path.exists(pause_flag_file):
        if not was_paused:
            logger.info(f"[W:{worker_id}] Задача {task_id[:6]} на паузе... Сохранение processed_urls.")
            with processed_urls_lock: current_proc_set_copy = processed_urls_set.copy()
            update_competitor_config_field(competitor_name, 'processed_urls', list(current_proc_set_copy))
            print(f"PAUSED::{task_id}::Парсинг на паузе (Worker {worker_id})...", flush=True)
            was_paused = True
        time.sleep(PAUSE_CHECK_INTERVAL)
    if was_paused: logger.info(f"[W:{worker_id}] Задача {task_id[:6]} возобновлена.")

    logger.debug(f"[W:{worker_id}] Начало обработки {url}")
    page_result = parse_page(url, config)
    saved_successfully = False; error_occurred = False

    if isinstance(page_result, dict):
        parse_error = page_result.get('parse_error')
        if parse_error: error_occurred = True
        should_save = (page_result.get('views') is not None or page_result.get('published_page') is not None) and not parse_error
        should_mark_processed = not parse_error or parse_error == 'missing_selectors'
        if should_save:
            with save_lock:
                if save_incremental_data(page_result, competitor_name): saved_successfully = True
                else: error_occurred = True; should_mark_processed = False
        if should_mark_processed:
            with processed_urls_lock:
                processed_urls_set.add(url)
                with results_lock: counters['processed'] += 1
    else: logger.error(f"[W:{worker_id}] parse_page не словарь для {url}: {type(page_result)}"); error_occurred = True

    with results_lock:
        if saved_successfully: counters['saved'] += 1
        if error_occurred: counters['errors'] += 1

    logger.debug(f"[W:{worker_id}] Завершение {url}. Saved:{saved_successfully}, Error:{error_occurred}")
    return url

# --- Основная логика ---
def main():
    global PROXIES
    PROXIES = load_proxies_from_file()
    parser = argparse.ArgumentParser(description="Парсер конкурентов.");
    parser.add_argument('--competitor', required=True);
    parser.add_argument('--full', action='store_true')
    parser.add_argument('--task-id', required=True, help="ID задачи")
    args = parser.parse_args();
    c_name = args.competitor; full = args.full; task_id = args.task_id

    logger.info(f"--- Парсер: '{c_name}'. Task:{task_id[:6]}. Режим:{'ПОЛН.' if full else 'ИНКР.'}. Потоков:{MAX_WORKERS}. Прокси:{len(PROXIES)} ---")

    all_configs=load_competitors_config();
    if not all_configs or c_name not in all_configs: logger.error(f"Нет конфига для '{c_name}'."); sys.exit(1)
    config=all_configs[c_name]
    config['_competitor_name_'] = c_name
    s_urls=config.get('sitemap_urls',[]); use_proxy=config.get('use_proxy', False)

    if not s_urls: logger.error(f"Нет URL карт для '{c_name}'."); sys.exit(1)
    logger.info(f"{len(s_urls)} URL карт сайта. Исп.прокси: {use_proxy}")
    all_p_urls=[]; proc_smaps=set()
    for s_url in s_urls: urls=get_urls_from_sitemap(s_url, use_proxy, proc_smaps); all_p_urls.extend(urls); logger.info(f"{s_url}: {len(urls)} URL. Всего уник.: {len(set(all_p_urls))}")
    unique_p_urls=list(set(all_p_urls)); total_found=len(unique_p_urls)
    logger.info(f"Всего найдено {total_found} уник. URL.")
    if not unique_p_urls:
        logger.warning(f"Нет URL для парсинга '{c_name}'.");
        if full: update_competitor_config_field(c_name, 'last_full_parse_stats', {'timestamp':datetime.now(timezone.utc).isoformat(),'found_count':0,'processed_count':0,'new_count':0,'error_count':0})
        sys.exit(0)

    urls_to_p=[]; proc_set=set(config.get('processed_urls',[]))
    if full: urls_to_p=unique_p_urls; logger.info("Полный парсинг: все URL."); proc_set=set()
    else: urls_to_p=[u for u in unique_p_urls if u not in proc_set]; logger.info(f"Инкр. парсинг: {len(urls_to_p)} новых URL (Всего:{total_found}, Обр.:{len(proc_set)}).")

    total_to_p=len(urls_to_p)
    if total_to_p==0 and not full: logger.info("Нет новых URL."); sys.exit(0)

    os.makedirs(FLAGS_DIR, exist_ok=True)
    pause_flag_file = os.path.join(FLAGS_DIR, f"pause_{task_id}.flag")

    processed_urls_lock = Lock(); results_lock = Lock(); save_lock = Lock()
    counters = {'processed': 0, 'saved': 0, 'errors': 0}
    completed_count = 0

    print(f"PROGRESS_UPDATE::task_id={task_id}::current=0::total={total_to_p}", flush=True)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(process_url_worker, url, config, task_id, save_lock, results_lock, processed_urls_lock, proc_set, counters): url for url in urls_to_p}
        logger.info(f"Отправлено {len(futures)} задач в {MAX_WORKERS} потоков.")

        for future in as_completed(futures):
            url = futures[future]
            completed_count += 1
            try:
                future.result()
            except Exception as exc:
                logger.error(f"Ошибка в потоке при обработке {url}: {exc}", exc_info=True)
                with results_lock:
                    counters['errors'] += 1

            if completed_count % CONFIG_UPDATE_FREQUENCY == 0 or completed_count == total_to_p:
                print(f"PROGRESS_UPDATE::task_id={task_id}::current={completed_count}::total={total_to_p}", flush=True)
                with processed_urls_lock: current_proc_set_copy = proc_set.copy()
                current_config = load_competitors_config()
                if current_config and c_name in current_config:
                    config_proc_set = set(current_config[c_name].get('processed_urls', []))
                    if current_proc_set_copy != config_proc_set: update_competitor_config_field(c_name, 'processed_urls', list(current_proc_set_copy))
                    else: logger.debug("Пропуск обновления processed_urls - нет изменений.")
                else: update_competitor_config_field(c_name, 'processed_urls', list(current_proc_set_copy))

    logger.info(f"Парсинг завершен. Всего задач: {total_to_p}. Обработано: {counters['processed']}. Сохранено: {counters['saved']}. Ошибок: {counters['errors']}.")
    update_competitor_config_field(c_name, 'processed_urls', list(proc_set)) # Финальное обновление

    if full:
        full_stats={'timestamp':datetime.now(timezone.utc).isoformat(),'found_count':total_found,'processed_count':len(proc_set),'new_count':counters['saved'],'error_count':counters['errors']}
        if not update_competitor_config_field(c_name, 'last_full_parse_stats', full_stats): logger.error("Не удалось обновить стат. полного парсинга!")

    if os.path.exists(pause_flag_file):
        try: os.remove(pause_flag_file)
        except OSError as e: logger.error(f"Не удален флаг паузы {pause_flag_file}: {e}")
    logger.info(f"--- Парсер '{c_name}' завершил работу ---"); sys.exit(0)

if __name__ == '__main__':
    main()