import feedparser
import requests
from lxml import html
from cssselect import GenericTranslator
import pandas as pd
import os
import datetime
import json
import time
import logging
import random
import argparse
from fake_useragent import UserAgent
import socket
import ssl
from urllib3.exceptions import InsecureRequestWarning
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import locale

# Устанавливаем локализацию для форматирования даты
try:
    locale.setlocale(locale.LC_TIME, 'ru_RU.UTF-8')  # Для Linux/Mac
except:
    try:
        locale.setlocale(locale.LC_TIME, 'Russian_Russia.1251')  # Для Windows
    except:
        pass  # Если не удалось установить русскую локаль

# Форматы даты
DATE_FORMAT = '%d.%m.%Y %H:%M'
DATE_FORMAT_SHORT = '%d.%m.%Y'

# Отключаем предупреждения о непроверенных SSL сертификатах
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Настройка логирования
logging.basicConfig(
    filename='parser.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    encoding='utf-8'  # Явно указываем кодировку для логов
)

# Консольный обработчик для вывода логов в консоль
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logging.getLogger().addHandler(console_handler)

# Список прокси для ротации (замените на свои)
PROXIES = [
    # {'http': 'http://username:password@proxy1.example.com:8080', 'https': 'https://username:password@proxy1.example.com:8080'},
    # Добавьте больше прокси при необходимости
]

# Глобальный счетчик прогресса
progress_counter = 0
total_items = 0
progress_lock = threading.Lock()

def update_progress(increment=1):
    """Обновляет и выводит прогресс парсинга"""
    global progress_counter, total_items
    with progress_lock:
        progress_counter += increment
        if total_items > 0:
            percentage = (progress_counter / total_items) * 100
            sys.stdout.write(f"Прогресс парсинга: {progress_counter}/{total_items} ({percentage:.1f}%)\n")
            sys.stdout.flush()

def format_date(date_obj):
    """Форматирует дату в нужный формат"""
    if not date_obj:
        return ""
    try:
        if isinstance(date_obj, str):
            date_obj = pd.to_datetime(date_obj)
        return date_obj.strftime(DATE_FORMAT)
    except:
        return str(date_obj)

def format_date_short(date_obj):
    """Форматирует дату в краткий формат"""
    if not date_obj:
        return ""
    try:
        if isinstance(date_obj, str):
            date_obj = pd.to_datetime(date_obj)
        return date_obj.strftime(DATE_FORMAT_SHORT)
    except:
        return str(date_obj)

# Класс для работы с данными конкурентов
class CompetitorTracker:
    def __init__(self, config_file='competitors.json'):
        self.config_file = config_file
        self.competitors = self.load_config()
        self.data_folder = 'data'
        
        # Создаем генератор случайных User-Agent
        try:
            self.ua = UserAgent()
        except:
            self.ua = None
            logging.warning("Не удалось инициализировать UserAgent, будет использован стандартный список")
        
        # Создаем папку для хранения данных, если её нет
        if not os.path.exists(self.data_folder):
            os.makedirs(self.data_folder)
    
    def load_config(self):
        """Загрузка конфигурации из JSON-файла"""
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                config = json.load(f)
                
                # Обновляем старые записи для совместимости
                for name, competitor in config.items():
                    if 'rss_url' in competitor and 'source_type' not in competitor:
                        competitor['source_type'] = 'rss'
                        competitor['source_url'] = competitor['rss_url']
                        del competitor['rss_url']
                    
                    # Миграция с "views_xpath" на "views_selector" и т.д.
                    if 'views_xpath' in competitor and 'views_selector' not in competitor:
                        competitor['selector_type'] = 'xpath'
                        competitor['views_selector'] = competitor['views_xpath']
                        competitor['date_selector'] = competitor['date_xpath']
                        del competitor['views_xpath']
                        del competitor['date_xpath']
                    
                    # Добавляем поле для полного парсинга, если его нет
                    if 'last_full_parse' not in competitor:
                        competitor['last_full_parse'] = None
                
                return config
        except FileNotFoundError:
            logging.error(f"Файл конфигурации {self.config_file} не найден")
            # Создаём пустой файл конфигурации
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump({}, f, ensure_ascii=False, indent=4)
            return {}
    
    def save_config(self):
        """Сохранение конфигурации в JSON-файл"""
        with open(self.config_file, 'w', encoding='utf-8') as f:
            json.dump(self.competitors, f, ensure_ascii=False, indent=4)
    
    def add_competitor(self, name, source_type, source_url, selector_type, views_selector, date_selector):
        """Добавление нового конкурента для отслеживания"""
        self.competitors[name] = {
            'source_type': source_type,
            'source_url': source_url,
            'selector_type': selector_type,
            'views_selector': views_selector,
            'date_selector': date_selector,
            'last_check': None,
            'last_full_parse': None,
            'processed_urls': []
        }
        self.save_config()
        logging.info(f"Добавлен новый конкурент: {name}")
    
    def delete_competitor(self, name):
        """Удаление конкурента"""
        if name in self.competitors:
            del self.competitors[name]
            self.save_config()
            logging.info(f"Удален конкурент: {name}")
            return True
        return False
    
    def get_random_headers(self):
        """Генерирует случайные заголовки для запроса"""
        if self.ua:
            user_agent = self.ua.random
        else:
            user_agents = [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/124.0',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
                'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            ]
            user_agent = random.choice(user_agents)
        
        return {
            'User-Agent': user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0',
            'Sec-Ch-Ua': '"Chromium";v="119", "Not?A_Brand";v="24"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"Windows"',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Referer': 'https://www.google.com/'
        }
    
    def get_random_proxy(self):
        """Возвращает случайный прокси из списка"""
        if PROXIES:
            return random.choice(PROXIES)
        return None
    
    def get_rss_items(self, rss_url):
        """Получение элементов из RSS-ленты"""
        try:
            # Настраиваем повышенные тайм-ауты для более надежного соединения
            socket.setdefaulttimeout(30)
            
            # Используем контекстный менеджер для установки временных настроек SSL
            original_context = ssl._create_default_https_context
            ssl._create_default_https_context = ssl._create_unverified_context
            
            logging.info(f"Получение RSS из {rss_url}")
            
            try:
                feed = feedparser.parse(rss_url)
            finally:
                # Восстанавливаем оригинальный контекст SSL
                ssl._create_default_https_context = original_context
            
            if not feed.entries:
                logging.warning(f"RSS-лента не содержит записей: {rss_url}")
                return []
            
            logging.info(f"Получено {len(feed.entries)} элементов из RSS")
            return feed.entries
        except Exception as e:
            logging.error(f"Ошибка при получении RSS: {e}")
            return []
    
    def get_sitemap_items(self, sitemap_url):
        """Получение URL из XML-карты сайта"""
        try:
            headers = self.get_random_headers()
            proxies = self.get_random_proxy()
            
            logging.info(f"Получение Sitemap из {sitemap_url}")
            
            response = requests.get(
                sitemap_url, 
                headers=headers, 
                proxies=proxies, 
                timeout=30,
                verify=False
            )
            
            if response.status_code != 200:
                logging.error(f"Ошибка при получении sitemap: {response.status_code}")
                return []
            
            # Парсим XML
            root = html.fromstring(response.content)
            
            # Пробуем несколько вариантов XPath для поиска URL в sitemap
            namespaces = {'ns': 'http://www.sitemaps.org/schemas/sitemap/0.9'}
            urls = root.xpath('//ns:url/ns:loc/text()', namespaces=namespaces)
            
            if not urls:
                # Пробуем без пространства имен
                urls = root.xpath('//url/loc/text()')
            
            if not urls:
                # Проверяем, не является ли это индексом sitemap
                sitemaps = root.xpath('//ns:sitemap/ns:loc/text()', namespaces=namespaces)
                
                if not sitemaps:
                    sitemaps = root.xpath('//sitemap/loc/text()')
                
                if sitemaps:
                    # Это индекс sitemap, обрабатываем каждую подкарту
                    all_urls = []
                    for sub_sitemap in sitemaps:  # Обрабатываем все подкарты для полного парсинга
                        sub_urls = self.get_sitemap_items(sub_sitemap)
                        all_urls.extend(sub_urls)
                        time.sleep(random.uniform(2.0, 5.0))  # Пауза между запросами
                    
                    return all_urls
            
            # Преобразуем в формат, подобный RSS
            items = []
            for url in urls:
                items.append({
                    'link': url,
                    'title': url.split('/')[-1]  # Используем последнюю часть URL как заголовок
                })
            
            logging.info(f"Получено {len(items)} элементов из Sitemap")
            return items
        except Exception as e:
            logging.error(f"Ошибка при получении sitemap: {e}")
            return []
    
    def parse_article(self, url, selector_type, views_selector, date_selector, retries=3):
        """Парсинг отдельной статьи для получения просмотров и даты"""
        for attempt in range(retries):
            try:
                headers = self.get_random_headers()
                proxies = self.get_random_proxy()
                
                # Добавляем случайную задержку между запросами
                time.sleep(random.uniform(1.5, 5.0))
                
                response = requests.get(
                    url, 
                    headers=headers, 
                    proxies=proxies, 
                    timeout=20,
                    verify=False  # Отключаем проверку SSL
                )
                
                if response.status_code != 200:
                    logging.error(f"Ошибка при получении страницы {url}: {response.status_code}")
                    if attempt < retries - 1:
                        time.sleep(random.uniform(5.0, 10.0))  # Увеличиваем задержку при ошибке
                        continue
                    return None, None
                
                tree = html.fromstring(response.content)
                
                # Получаем данные в зависимости от типа селектора
                if selector_type == 'xpath':
                    views_element = tree.xpath(views_selector)
                    date_element = tree.xpath(date_selector)
                else:  # css
                    views_element = tree.cssselect(views_selector)
                    date_element = tree.cssselect(date_selector)
                
                views = views_element[0].text_content().strip() if views_element else "Не найдено"
                date = date_element[0].text_content().strip() if date_element else "Не найдено"
                
                # Очистка и нормализация данных
                views = re.sub(r'\s+', ' ', views).strip()
                date = re.sub(r'\s+', ' ', date).strip()
                
                # Удаляем начальные и конечные не-алфавитно-цифровые символы
                views = views.strip('.,; \t\n\r')
                date = date.strip('.,; \t\n\r')
                
                update_progress()
                return views, date
            except requests.exceptions.RequestException as e:
                logging.error(f"Ошибка соединения при парсинге статьи {url}: {e}")
                if attempt < retries - 1:
                    time.sleep(random.uniform(5.0, 10.0))
                else:
                    update_progress()
                    return None, None
            except Exception as e:
                logging.error(f"Ошибка при парсинге статьи {url}: {e}")
                if attempt < retries - 1:
                    time.sleep(random.uniform(5.0, 10.0))
                else:
                    update_progress()
                    return None, None
        
        return None, None
    
    def parse_item(self, item, selector_type, views_selector, date_selector, processed_urls, full_parse):
        """Парсинг одного элемента (статьи)"""
        url = item.get('link', '')
        
        # Проверяем, не обрабатывали ли мы уже эту ссылку
        is_new = url not in processed_urls
        
        # Если это не полный парсинг и URL уже обработан, пропускаем
        if not full_parse and not is_new:
            update_progress()
            return None
        
        title = item.get('title', url.split('/')[-1])
        published = item.get('published', 'Не указано')
        
        # Парсим просмотры и дату со страницы
        views, page_date = self.parse_article(url, selector_type, views_selector, date_selector)
        
        if views is None or page_date is None:
            logging.warning(f"Не удалось получить данные для {url}")
            return None
        
        # Формируем данные
        result = {
            'title': title,
            'url': url,
            'published_rss': published,
            'published_page': page_date,
            'views': views,
            'check_date': datetime.datetime.now().strftime('%Y-%m-%d'),
            'is_new': is_new  # Флаг для определения новых URL
        }
        
        return result
    
    def find_existing_data(self, competitor_name, url):
        """Находит существующие данные для URL в ранее сохраненных CSV"""
        for file in os.listdir(self.data_folder):
            if file.startswith(f"{competitor_name}_") and file.endswith('.csv'):
                file_path = os.path.join(self.data_folder, file)
                try:
                    df = pd.read_csv(file_path)
                    # Ищем URL в данных
                    matching_rows = df[df['url'] == url]
                    if not matching_rows.empty:
                        return matching_rows.iloc[0].to_dict()
                except Exception as e:
                    logging.error(f"Ошибка при чтении файла {file}: {e}")
        return None
    
    def track_competitors(self, competitor_name=None, full_parse=False):
        """Основная функция для отслеживания всех конкурентов"""
        global total_items, progress_counter
        current_date = datetime.datetime.now().strftime('%Y-%m-%d')
        
        # Сбрасываем прогресс
        total_items = 0
        progress_counter = 0
        
        competitors_to_track = {}
        if competitor_name:
            if competitor_name in self.competitors:
                competitors_to_track[competitor_name] = self.competitors[competitor_name]
            else:
                logging.error(f"Конкурент {competitor_name} не найден")
                return
        else:
            competitors_to_track = self.competitors
        
        for name, config in competitors_to_track.items():
            logging.info(f"Обработка конкурента: {name}")
            
            source_type = config.get('source_type', 'rss')  # По умолчанию RSS
            source_url = config.get('source_url', config.get('rss_url', ''))  # Поддержка старого формата
            selector_type = config.get('selector_type', 'xpath')  # По умолчанию XPath
            
            # Поддержка старого формата с views_xpath/date_xpath
            if 'views_selector' in config:
                views_selector = config['views_selector']
                date_selector = config['date_selector']
            else:
                views_selector = config.get('views_xpath', '')
                date_selector = config.get('date_xpath', '')
            
            processed_urls = config.get('processed_urls', [])
            
            # Получаем элементы для обработки в зависимости от типа источника
            if source_type == 'rss':
                items = self.get_rss_items(source_url)
            else:  # sitemap
                items = self.get_sitemap_items(source_url)
            
            # Устанавливаем общее количество элементов для прогресс-бара
            total_items = len(items)
            logging.info(f"Будет обработано {total_items} элементов для {name}")
            sys.stdout.write(f"Всего элементов для парсинга: {total_items}\n")
            sys.stdout.flush()
            
            new_data = []
            updated_data = []
            
            # Используем многопоточность для ускорения парсинга
            with ThreadPoolExecutor(max_workers=5) as executor:
                future_to_item = {
                    executor.submit(
                        self.parse_item, 
                        item, 
                        selector_type, 
                        views_selector, 
                        date_selector, 
                        processed_urls,
                        full_parse
                    ): item for item in items
                }
                
                for future in as_completed(future_to_item):
                    result = future.result()
                    if result:
                        url = result['url']
                        is_new = result['is_new']
                        del result['is_new']  # Удаляем служебное поле
                        
                        # Добавляем URL в список обработанных, если он новый
                        if is_new and url not in processed_urls:
                            processed_urls.append(url)
                            new_data.append(result)
                        elif not is_new:
                            # Обновляем существующие данные (просмотры)
                            updated_data.append(result)
            
            # Обновляем конфигурацию
            self.competitors[name]['processed_urls'] = processed_urls
            self.competitors[name]['last_check'] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            if full_parse:
                self.competitors[name]['last_full_parse'] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            self.save_config()
            
            # Сохраняем данные для новых URL
            if new_data:
                df_new = pd.DataFrame(new_data)
                data_file = os.path.join(self.data_folder, f"{name}_{current_date}.csv")
                
                # Если файл существует, дополняем его
                if os.path.exists(data_file):
                    df_new.to_csv(data_file, mode='a', header=False, index=False, encoding='utf-8')
                else:
                    df_new.to_csv(data_file, index=False, encoding='utf-8')
                
                logging.info(f"Сохранено {len(new_data)} новых статей для {name}")
            
            # Обновляем данные для существующих URL
            if updated_data and full_parse:
                logging.info(f"Обновлено {len(updated_data)} существующих статей для {name}")
                
                # Создаем датафрейм с обновленными данными
                df_updated = pd.DataFrame(updated_data)
                
                # Обновляем данные в существующих файлах
                for file in os.listdir(self.data_folder):
                    if file.startswith(f"{name}_") and file.endswith('.csv'):
                        file_path = os.path.join(self.data_folder, file)
                        try:
                            df = pd.read_csv(file_path)
                            
                            # Для каждой обновленной записи
                            for _, row in df_updated.iterrows():
                                url = row['url']
                                # Находим соответствующую строку
                                mask = df['url'] == url
                                if mask.any():
                                    # Обновляем просмотры и дату проверки
                                    df.loc[mask, 'views'] = row['views']
                                    df.loc[mask, 'check_date'] = current_date
                            
                            # Сохраняем обновленный файл
                            df.to_csv(file_path, index=False, encoding='utf-8')
                        except Exception as e:
                            logging.error(f"Ошибка при обновлении файла {file}: {e}")
            
            if not new_data and not updated_data:
                logging.info(f"Новых или обновленных статей для {name} не найдено")

# Функция для выполнения парсинга
def run_parser(competitor_name=None, full_parse=False):
    tracker = CompetitorTracker()
    tracker.track_competitors(competitor_name, full_parse)
    logging.info("Парсинг завершен")
    sys.stdout.write("Парсинг завершен успешно.\n")
    sys.stdout.flush()

# Запускаем парсер, если файл запущен напрямую
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Парсер статей конкурентов')
    parser.add_argument('--competitor', help='Имя конкурента для парсинга')
    parser.add_argument('--full', action='store_true', help='Выполнить полный парсинг, включая обновление существующих данных')
    
    args = parser.parse_args()
    
    run_parser(args.competitor, args.full)