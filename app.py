from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
import pandas as pd
import os
import json
import plotly
import plotly.express as px
from datetime import datetime, timedelta
import requests
from lxml import html
from cssselect import GenericTranslator
import random
import time
import feedparser
import uuid
import subprocess
import sys
import logging
import flask_socketio
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import threading
import re
import locale

# Устанавливаем локализацию для форматирования даты
try:
    locale.setlocale(locale.LC_TIME, 'ru_RU.UTF-8')  # Для Linux/Mac
except:
    try:
        locale.setlocale(locale.LC_TIME, 'Russian_Russia.1251')  # Для Windows
    except:
        pass  # Если не удалось установить русскую локаль

app = Flask(__name__)
app.secret_key = 'your_secure_secret_key_here'  # Замените на свой секретный ключ
socketio = flask_socketio.SocketIO(app)

# Настройка логирования
log_format = '%(asctime)s - %(levelname)s - %(message)s'
logging.basicConfig(
    filename='parser.log',
    level=logging.INFO,
    format=log_format,
    encoding='utf-8'  # Явно указываем кодировку для логов
)

# Консольный обработчик для вывода логов в консоль
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter(log_format))
logging.getLogger().addHandler(console_handler)

# Настройка менеджера авторизации
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Путь к папкам и файлам
DATA_FOLDER = 'data'
CONFIG_FILE = 'competitors.json'
USERS_FILE = 'users.json'

# Словарь с активными процессами парсинга
parsing_processes = {}

# Список User-Agent для ротации
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/124.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
]

# Список прокси для ротации (замените на свои)
PROXIES = [
    # {'http': 'http://username:password@proxy1.example.com:8080', 'https': 'https://username:password@proxy1.example.com:8080'},
    # Добавьте больше прокси при необходимости
]

# Формат даты для отображения
DATE_FORMAT = '%d.%m.%Y %H:%M'
DATE_FORMAT_SHORT = '%d.%m.%Y'

class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash

def load_users():
    """Загрузка пользователей из файла"""
    try:
        with open(USERS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        # Создаем файл с пользователем по умолчанию
        default_users = {
            '1': {
                'username': 'admin',
                'password_hash': generate_password_hash('admin')  # Пароль по умолчанию - 'admin'
            }
        }
        with open(USERS_FILE, 'w', encoding='utf-8') as f:
            json.dump(default_users, f, ensure_ascii=False, indent=4)
        return default_users

def save_users(users):
    """Сохранение пользователей в файл"""
    with open(USERS_FILE, 'w', encoding='utf-8') as f:
        json.dump(users, f, ensure_ascii=False, indent=4)

@login_manager.user_loader
def load_user(user_id):
    users = load_users()
    if user_id in users:
        user_data = users[user_id]
        return User(user_id, user_data['username'], user_data['password_hash'])
    return None

def get_random_headers():
    """Генерирует случайные заголовки для запроса"""
    user_agent = random.choice(USER_AGENTS)
    return {
        'User-Agent': user_agent,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Cache-Control': 'max-age=0',
        'TE': 'Trailers',
    }

def get_proxy():
    """Возвращает случайный прокси из списка"""
    if PROXIES:
        return random.choice(PROXIES)
    return None

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

def load_competitors():
    """Загрузка информации о конкурентах из конфиг-файла"""
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            competitors = json.load(f)
            
            # Обновляем старые записи для совместимости
            for name, config in competitors.items():
                if 'selector_type' not in config:
                    config['selector_type'] = 'xpath'  # По умолчанию XPath
                if 'rss_url' in config and 'source_type' not in config:
                    config['source_type'] = 'rss'
                    config['source_url'] = config['rss_url']
                    del config['rss_url']
                if 'last_full_parse' not in config:
                    config['last_full_parse'] = None
            
            return competitors
    except FileNotFoundError:
        # Если файл не найден, создаем пустой словарь
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump({}, f, ensure_ascii=False, indent=4)
        return {}

def save_competitors(competitors):
    """Сохранение информации о конкурентах в конфиг-файл"""
    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
        json.dump(competitors, f, ensure_ascii=False, indent=4)

def get_all_data():
    """Получение всех данных из CSV-файлов"""
    all_data = []
    
    for file in os.listdir(DATA_FOLDER):
        if file.endswith('.csv'):
            file_path = os.path.join(DATA_FOLDER, file)
            try:
                df = pd.read_csv(file_path)
                
                # Извлекаем имя конкурента из имени файла (формат: конкурент_дата.csv)
                parts = file.split('_')
                if len(parts) >= 2:
                    competitor_name = parts[0]
                    check_date = parts[1].replace('.csv', '')
                else:
                    competitor_name = "unknown"
                    check_date = "unknown"
                
                df['competitor'] = competitor_name
                
                # Преобразуем строки просмотров в числа
                if 'views' in df.columns:
                    df['views_num'] = pd.to_numeric(df['views'].str.replace('[^0-9]', '', regex=True), 
                                                errors='coerce')
                else:
                    df['views_num'] = 0
                
                # Преобразуем даты с явным указанием формата
                if 'check_date' in df.columns:
                    df['check_date'] = pd.to_datetime(df['check_date'], format='%Y-%m-%d', errors='coerce')
                else:
                    df['check_date'] = pd.to_datetime(check_date, format='%Y-%m-%d', errors='coerce')
                
                # Преобразуем даты публикации
                if 'published_page' in df.columns:
                    df['published_page_date'] = pd.to_datetime(df['published_page'], errors='coerce')
                
                all_data.append(df)
            except Exception as e:
                logging.error(f"Ошибка при чтении файла {file}: {e}")
    
    if all_data:
        return pd.concat(all_data, ignore_index=True)
    else:
        return pd.DataFrame()

def get_competitor_stats():
    """Получение статистики по конкурентам для главной страницы"""
    data = get_all_data()
    competitors = load_competitors()
    stats = []
    
    if data.empty:
        return []
    
    # Для каждого конкурента
    for name, config in competitors.items():
        comp_data = data[data['competitor'] == name]
        
        # Общее количество статей
        total_articles = len(comp_data)
        
        # Получение даты последней проверки
        last_check = config.get('last_check', 'Не проводилась')
        if last_check and last_check != 'Не проводилась':
            last_check = format_date(last_check)
        
        # Дата последнего полного парсинга
        last_full_parse = config.get('last_full_parse', 'Не проводился')
        if last_full_parse and last_full_parse != 'Не проводился':
            last_full_parse = format_date(last_full_parse)
        
        # Количество статей за последний обход
        if last_check and last_check != 'Не проводилась':
            try:
                check_date = pd.to_datetime(config.get('last_check'))
                last_check_data = comp_data[comp_data['check_date'].dt.date == check_date.date()]
                last_articles_count = len(last_check_data)
            except:
                last_articles_count = 0
        else:
            last_articles_count = 0
        
        # Количество публикаций за последние 24 часа
        now = datetime.now()
        day_ago = now - timedelta(days=1)
        
        if 'published_page_date' in comp_data.columns:
            try:
                articles_last_24h = comp_data[comp_data['published_page_date'] >= day_ago]
                articles_24h_count = len(articles_last_24h)
            except:
                articles_24h_count = 0
        else:
            articles_24h_count = 0
        
        # Статус парсинга
        parsing_status = "Активен" if name in parsing_processes and parsing_processes[name]['process'].is_alive() else "Неактивен"
        
        stats.append({
            'name': name,
            'last_articles': last_articles_count,
            'total_articles': total_articles,
            'articles_24h': articles_24h_count,
            'last_check': last_check,
            'last_full_parse': last_full_parse,
            'parsing_status': parsing_status
        })
    
    return stats

def test_selectors(url, selector, selector_type, retries=2):
    """Тестирование селекторов (XPath или CSS) на странице"""
    try:
        headers = get_random_headers()
        proxies = get_proxy()
        
        for attempt in range(retries):
            try:
                response = requests.get(url, headers=headers, proxies=proxies, timeout=15)
                
                if response.status_code != 200:
                    if attempt < retries - 1:
                        time.sleep(random.uniform(1.0, 3.0))
                        continue
                    return {
                        'success': False,
                        'error': f"Ошибка получения страницы: {response.status_code}"
                    }
                
                tree = html.fromstring(response.content)
                
                # Получаем данные в зависимости от типа селектора
                if selector_type == 'xpath':
                    elements = tree.xpath(selector)
                else:  # css
                    elements = tree.cssselect(selector)
                
                if not elements:
                    return {
                        'success': False,
                        'error': f'Селектор не вернул результатов: {selector}'
                    }
                
                # Получаем текст всех найденных элементов
                results = [el.text_content().strip() if hasattr(el, 'text_content') else str(el) for el in elements[:5]]
                
                return {
                    'success': True,
                    'results': results,
                    'count': len(elements)
                }
            except requests.exceptions.RequestException as e:
                if attempt < retries - 1:
                    time.sleep(random.uniform(1.0, 3.0))
                else:
                    return {
                        'success': False,
                        'error': f"Ошибка соединения: {str(e)}"
                    }
    except Exception as e:
        return {
            'success': False,
            'error': str(e)
        }

def test_rss(rss_url):
    """Тестирование доступности RSS-ленты"""
    try:
        feed = feedparser.parse(rss_url)
        
        if hasattr(feed, 'status') and feed.status != 200:
            return {
                'success': False,
                'error': f"Ошибка при получении RSS: {feed.status}"
            }
        
        if not feed.entries:
            return {
                'success': False,
                'error': 'RSS-лента не содержит записей'
            }
        
        # Получаем первые 5 записей
        entries = []
        for entry in feed.entries[:5]:
            entries.append({
                'title': entry.title,
                'link': entry.link,
                'published': entry.get('published', 'Не указано')
            })
        
        return {
            'success': True,
            'entries': entries,
            'count': len(feed.entries)
        }
    except Exception as e:
        return {
            'success': False,
            'error': str(e)
        }

def test_sitemap(sitemap_url):
    """Тестирование доступности XML-карты сайта"""
    try:
        headers = get_random_headers()
        proxies = get_proxy()
        
        response = requests.get(sitemap_url, headers=headers, proxies=proxies, timeout=20, verify=False)
        
        if response.status_code != 200:
            return {
                'success': False,
                'error': f"Ошибка при получении sitemap: {response.status_code}"
            }
        
        # Парсим XML
        try:
            root = html.fromstring(response.content)
            
            # Пробуем различные варианты XPath для sitemap
            namespaces = {'ns': 'http://www.sitemaps.org/schemas/sitemap/0.9'}
            
            # Сначала пытаемся получить URL из стандартного sitemap
            urls = root.xpath('//ns:url/ns:loc/text()', namespaces=namespaces)
            
            if not urls:
                # Пробуем без пространства имен
                urls = root.xpath('//url/loc/text()')
            
            if not urls:
                # Проверяем, может это индекс sitemaps
                sitemaps = root.xpath('//ns:sitemap/ns:loc/text()', namespaces=namespaces)
                
                if not sitemaps:
                    sitemaps = root.xpath('//sitemap/loc/text()')
                
                if sitemaps:
                    # Это индекс sitemap
                    entries = []
                    for sitemap_url in sitemaps[:5]:
                        entries.append({
                            'url': sitemap_url,
                            'lastupdated': 'sitemap index'
                        })
                    
                    return {
                        'success': True,
                        'entries': entries,
                        'count': len(sitemaps),
                        'is_index': True
                    }
                else:
                    return {
                        'success': False,
                        'error': 'XML-карта не содержит URL-адресов или не является стандартной картой сайта'
                    }
            
            # Получаем первые 5 URL из sitemap
            entries = []
            for url in urls[:5]:
                entries.append({
                    'url': url,
                    'lastupdated': 'Не указано'  # Можно добавить извлечение lastmod если нужно
                })
            
            return {
                'success': True,
                'entries': entries,
                'count': len(urls),
                'is_index': False
            }
        except Exception as e:
            return {
                'success': False,
                'error': f"Ошибка парсинга XML: {str(e)}"
            }
    except Exception as e:
        return {
            'success': False,
            'error': str(e)
        }

def capture_parser_output(process, task_id):
    """Захватывает вывод процесса парсера и отправляет его через сокет"""
    for line in iter(process.stdout.readline, b''):
        try:
            # Исправляем декодирование, добавляя обработку ошибок
            line_text = line.decode('cp1251', errors="replace").strip()
            if line_text:
                # Отправляем лог через сокет
                socketio.emit('parsing_log', {
                    'task_id': task_id,
                    'log': line_text
                })
                
                # Обновляем статистику, если в логах есть информация о прогрессе
                if "Прогресс парсинга:" in line_text:
                    try:
                        # Извлекаем информацию о прогрессе
                        progress_match = re.search(r'Прогресс парсинга: (\d+)/(\d+)', line_text)
                        if progress_match:
                            current = int(progress_match.group(1))
                            total = int(progress_match.group(2))
                            percentage = round((current / total) * 100, 1) if total > 0 else 0
                            
                            socketio.emit('parsing_progress', {
                                'task_id': task_id,
                                'current': current,
                                'total': total,
                                'percentage': percentage
                            })
                    except Exception as e:
                        logging.error(f"Ошибка при обработке прогресса: {e}")
                
                # Также логируем в файл
                logging.info(f"[Task {task_id}] {line_text}")
        except Exception as e:
            logging.error(f"Ошибка при обработке вывода парсера: {e}")
    
    # Обновляем статистику
    socketio.emit('refresh_stats', {})
    
    # Когда процесс завершится, отправляем сообщение о завершении
    socketio.emit('parsing_finished', {
        'task_id': task_id
    })

@app.route('/')
@login_required
def index():
    """Главная страница"""
    stats = get_competitor_stats()
    return render_template('index.html', stats=stats)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Страница авторизации"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        users = load_users()
        user_found = False
        
        for user_id, user_data in users.items():
            if user_data['username'] == username:
                user_found = True
                if check_password_hash(user_data['password_hash'], password):
                    user = User(user_id, user_data['username'], user_data['password_hash'])
                    login_user(user, remember=True)
                    next_page = request.args.get('next')
                    return redirect(next_page or url_for('index'))
                else:
                    flash('Неверный пароль', 'danger')
                    break
        
        if not user_found:
            flash('Пользователь не найден', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """Выход из системы"""
    logout_user()
    flash('Вы успешно вышли из системы', 'success')
    return redirect(url_for('login'))

@app.route('/competitors')
@login_required
def competitors():
    """Страница управления конкурентами"""
    competitors_data = load_competitors()
    return render_template('competitors.html', competitors=competitors_data)

@app.route('/add_competitor', methods=['POST'])
@login_required
def add_competitor():
    """Добавление нового конкурента"""
    name = request.form.get('name').strip()
    source_type = request.form.get('source_type')  # 'rss' или 'sitemap'
    source_url = request.form.get('source_url').strip()
    selector_type = request.form.get('selector_type')  # 'xpath' или 'css'
    views_selector = request.form.get('views_selector').strip()
    date_selector = request.form.get('date_selector').strip()
    
    if not name or not source_type or not source_url or not selector_type or not views_selector or not date_selector:
        flash('Все поля обязательны для заполнения', 'danger')
        return redirect(url_for('competitors'))
    
    # Проверяем, что конкурент с таким именем не существует
    competitors = load_competitors()
    if name in competitors:
        flash(f'Конкурент с именем "{name}" уже существует', 'danger')
        return redirect(url_for('competitors'))
    
    # Добавляем нового конкурента
    competitors[name] = {
        'source_type': source_type,
        'source_url': source_url,
        'selector_type': selector_type,
        'views_selector': views_selector,
        'date_selector': date_selector,
        'last_check': None,
        'last_full_parse': None,
        'processed_urls': []
    }
    
    save_competitors(competitors)
    flash(f'Конкурент "{name}" успешно добавлен', 'success')
    return redirect(url_for('competitors'))

@app.route('/edit_competitor/<name>', methods=['GET', 'POST'])
@login_required
def edit_competitor(name):
    """Редактирование настроек конкурента"""
    competitors = load_competitors()
    
    if name not in competitors:
        flash(f'Конкурент "{name}" не найден', 'danger')
        return redirect(url_for('competitors'))
    
    if request.method == 'POST':
        source_type = request.form.get('source_type')
        source_url = request.form.get('source_url').strip()
        selector_type = request.form.get('selector_type')
        views_selector = request.form.get('views_selector').strip()
        date_selector = request.form.get('date_selector').strip()
        
        if not source_type or not source_url or not selector_type or not views_selector or not date_selector:
            flash('Все поля обязательны для заполнения', 'danger')
            return redirect(url_for('edit_competitor', name=name))
        
        # Обновляем настройки конкурента
        competitors[name]['source_type'] = source_type
        competitors[name]['source_url'] = source_url
        competitors[name]['selector_type'] = selector_type
        competitors[name]['views_selector'] = views_selector
        competitors[name]['date_selector'] = date_selector
        
        save_competitors(competitors)
        flash(f'Настройки конкурента "{name}" успешно обновлены', 'success')
        return redirect(url_for('competitors'))
    
    # GET запрос - отображаем форму редактирования
    return render_template('edit_competitor.html', name=name, config=competitors[name])

@app.route('/delete_competitor/<name>', methods=['POST'])
@login_required
def delete_competitor(name):
    """Удаление конкурента"""
    competitors = load_competitors()
    if name in competitors:
        del competitors[name]
        save_competitors(competitors)
        flash(f'Конкурент "{name}" успешно удален', 'success')
    else:
        flash(f'Конкурент "{name}" не найден', 'danger')
    
    return redirect(url_for('index'))

@app.route('/test_selector', methods=['POST'])
@login_required
def test_selector_route():
    """API для тестирования селекторов (XPath или CSS)"""
    url = request.form.get('url')
    selector = request.form.get('selector')
    selector_type = request.form.get('selector_type', 'xpath')  # 'xpath' или 'css'
    
    if not url or not selector:
        return jsonify({'success': False, 'error': 'URL и селектор обязательны'})
    
    result = test_selectors(url, selector, selector_type)
    return jsonify(result)

@app.route('/test_rss', methods=['POST'])
@login_required
def test_rss_route():
    """API для тестирования RSS"""
    rss_url = request.form.get('rss_url')
    
    if not rss_url:
        return jsonify({'success': False, 'error': 'URL RSS-ленты обязателен'})
    
    result = test_rss(rss_url)
    return jsonify(result)

@app.route('/test_sitemap', methods=['POST'])
@login_required
def test_sitemap_route():
    """API для тестирования Sitemap"""
    sitemap_url = request.form.get('sitemap_url')
    
    if not sitemap_url:
        return jsonify({'success': False, 'error': 'URL XML-карты сайта обязателен'})
    
    result = test_sitemap(sitemap_url)
    return jsonify(result)

@app.route('/manual_parse', methods=['POST'])
@login_required
def manual_parse():
    """Ручной запуск парсинга для конкретного конкурента"""
    name = request.form.get('name')
    full_parse = request.form.get('full_parse', '0') == '1'
    
    if not name:
        return jsonify({
            'success': False,
            'error': 'Имя конкурента обязательно'
        })
    
    # Проверяем, не запущен ли уже парсинг для этого конкурента
    if name in parsing_processes and parsing_processes[name]['process'].is_alive():
        return jsonify({
            'success': False,
            'error': f'Парсинг для конкурента "{name}" уже запущен'
        })
    
    try:
        # Запускаем парсер в отдельном процессе
        script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'competitor_parser.py')
        
        if not os.path.exists(script_path):
            return jsonify({
                'success': False,
                'error': f'Скрипт парсера не найден: {script_path}'
            })
        
        # Создаем уникальный ID для задачи
        task_id = str(uuid.uuid4())
        
        # Формируем команду с параметрами
        command = [sys.executable, script_path, '--competitor', name]
        
        # Добавляем флаг полного парсинга, если нужно
        if full_parse:
            command.extend(['--full'])
            # Обновляем дату последнего полного парсинга
            competitors = load_competitors()
            if name in competitors:
                competitors[name]['last_full_parse'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                save_competitors(competitors)
        
        # Запускаем процесс с перенаправлением вывода
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=1,
            universal_newlines=False
        )
        
        # Запускаем поток для чтения вывода процесса
        output_thread = threading.Thread(
            target=lambda: capture_parser_output(process, task_id),
            daemon=True
        )
        output_thread.start()
        
        # Сохраняем информацию о процессе
        parsing_processes[name] = {
            'process': output_thread,
            'task_id': task_id,
            'start_time': datetime.now().strftime(DATE_FORMAT),
            'is_full': full_parse
        }
        
        return jsonify({
            'success': True,
            'message': f'Запущен парсинг конкурента "{name}"',
            'task_id': task_id,
            'is_full': full_parse
        })
    except Exception as e:
        logging.error(f"Ошибка при запуске парсинга: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Ошибка при запуске парсинга: {str(e)}'
        })

@app.route('/parsing_status/<name>')
@login_required
def parsing_status(name):
    """Получение статуса парсинга для конкурента"""
    if name in parsing_processes:
        process_info = parsing_processes[name]
        is_running = process_info['process'].is_alive()
        
        return jsonify({
            'is_running': is_running,
            'task_id': process_info['task_id'],
            'start_time': process_info['start_time'],
            'is_full': process_info.get('is_full', False)
        })
    else:
        return jsonify({
            'is_running': False
        })

@app.route('/statistics')
@login_required
def statistics():
    """Страница со статистикой"""
    data = get_all_data()
    
    if data.empty:
        return render_template('statistics.html', error="Данные не найдены")
    
    # Фильтрация по конкуренту, если указан
    competitor = request.args.get('competitor')
    if competitor and competitor != 'all':
        data = data[data['competitor'] == competitor]
    
    # Фильтрация по дате, если указана
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    if start_date:
        data = data[data['check_date'] >= pd.to_datetime(start_date)]
    if end_date:
        data = data[data['check_date'] <= pd.to_datetime(end_date)]
    
    # Общая статистика
    total_articles = len(data)
    
    # Статистика по конкурентам
    competitor_stats = data['competitor'].value_counts().reset_index()
    competitor_stats.columns = ['competitor', 'count']
    
    # Топ-10 статей по просмотрам
    top_articles = data.sort_values('views_num', ascending=False).head(10)
    
    # Форматируем даты для отображения
    top_articles['formatted_check_date'] = top_articles['check_date'].apply(format_date)
    top_articles['formatted_published'] = top_articles['published_page'].apply(lambda x: x if isinstance(x, str) else format_date(x))
    
    # График просмотров по дням
    data['date_only'] = data['check_date'].dt.date
    views_by_date = data.groupby(['date_only', 'competitor'])['views_num'].mean().reset_index()
    
    fig = px.line(views_by_date, x='date_only', y='views_num', color='competitor',
                 title='Средние просмотры статей по дням')
    views_chart = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
    
    # График распределения статей по конкурентам
    fig2 = px.pie(competitor_stats, values='count', names='competitor',
                 title='Распределение статей по конкурентам')
    competitor_chart = json.dumps(fig2, cls=plotly.utils.PlotlyJSONEncoder)
    
    return render_template('statistics.html', 
                          total_articles=total_articles,
                          competitor_stats=competitor_stats.to_dict('records'),
                          top_articles=top_articles.to_dict('records'),
                          views_chart=views_chart,
                          competitor_chart=competitor_chart)

@app.route('/data')
@login_required
def get_data():
    """API для получения данных в формате JSON"""
    data = get_all_data()
    
    if data.empty:
        return jsonify({"error": "Данные не найдены"})
    
    # Фильтрация по конкуренту, если указан
    competitor = request.args.get('competitor')
    if competitor and competitor != 'all':
        data = data[data['competitor'] == competitor]
    
    # Преобразуем даты в строки для JSON
    data['check_date'] = data['check_date'].dt.strftime(DATE_FORMAT_SHORT)
    
    return jsonify(data.to_dict('records'))

@app.route('/competitors_api')
@login_required
def get_competitors():
    """API для получения списка конкурентов"""
    competitors = load_competitors()
    return jsonify(list(competitors.keys()))

@app.route('/refresh_stats')
@login_required
def refresh_stats():
    """API для обновления статистики"""
    stats = get_competitor_stats()
    return jsonify({
        'success': True,
        'stats': stats
    })

@app.route('/users')
@login_required
def users():
    """Страница управления пользователями"""
    # Только admin может управлять пользователями
    if current_user.username != 'admin':
        flash('Доступ запрещен', 'danger')
        return redirect(url_for('index'))
    
    users_data = load_users()
    users_list = []
    
    for user_id, user_data in users_data.items():
        users_list.append({
            'id': user_id,
            'username': user_data['username']
        })
    
    return render_template('users.html', users=users_list)

@app.route('/add_user', methods=['POST'])
@login_required
def add_user():
    """Добавление нового пользователя"""
    # Только admin может добавлять пользователей
    if current_user.username != 'admin':
        flash('Доступ запрещен', 'danger')
        return redirect(url_for('index'))
    
    username = request.form.get('username').strip()
    password = request.form.get('password')
    password_confirm = request.form.get('password_confirm')
    
    if not username or not password:
        flash('Все поля обязательны для заполнения', 'danger')
        return redirect(url_for('users'))
    
    if password != password_confirm:
        flash('Пароли не совпадают', 'danger')
        return redirect(url_for('users'))
    
    # Проверяем, что пользователь с таким именем не существует
    users_data = load_users()
    for user_id, user_data in users_data.items():
        if user_data['username'] == username:
            flash(f'Пользователь с именем "{username}" уже существует', 'danger')
            return redirect(url_for('users'))
    
    # Генерируем новый ID
    new_id = str(max([int(user_id) for user_id in users_data.keys()]) + 1)
    
    # Добавляем нового пользователя
    users_data[new_id] = {
        'username': username,
        'password_hash': generate_password_hash(password)
    }
    
    save_users(users_data)
    flash(f'Пользователь "{username}" успешно добавлен', 'success')
    return redirect(url_for('users'))

@app.route('/delete_user/<user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    """Удаление пользователя"""
    # Только admin может удалять пользователей
    if current_user.username != 'admin':
        flash('Доступ запрещен', 'danger')
        return redirect(url_for('index'))
    
    # Не позволяем удалить пользователя admin
    users_data = load_users()
    if user_id in users_data and users_data[user_id]['username'] == 'admin':
        flash('Невозможно удалить пользователя admin', 'danger')
        return redirect(url_for('users'))
    
    if user_id in users_data:
        username = users_data[user_id]['username']
        del users_data[user_id]
        save_users(users_data)
        flash(f'Пользователь "{username}" успешно удален', 'success')
    else:
        flash(f'Пользователь с ID {user_id} не найден', 'danger')
    
    return redirect(url_for('users'))

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Изменение пароля пользователя"""
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        new_password_confirm = request.form.get('new_password_confirm')
        
        if not current_password or not new_password or not new_password_confirm:
            flash('Все поля обязательны для заполнения', 'danger')
            return redirect(url_for('change_password'))
        
        if new_password != new_password_confirm:
            flash('Новые пароли не совпадают', 'danger')
            return redirect(url_for('change_password'))
        
        # Проверяем текущий пароль
        users_data = load_users()
        if current_user.id in users_data:
            user_data = users_data[current_user.id]
            if check_password_hash(user_data['password_hash'], current_password):
                # Обновляем пароль
                users_data[current_user.id]['password_hash'] = generate_password_hash(new_password)
                save_users(users_data)
                flash('Пароль успешно изменен', 'success')
                return redirect(url_for('index'))
            else:
                flash('Текущий пароль неверен', 'danger')
        else:
            flash('Ошибка при изменении пароля', 'danger')
    
    return render_template('change_password.html')

@socketio.on('connect')
def socket_connect():
    if not current_user.is_authenticated:
        return False

@socketio.on('get_parsing_status')
def socket_get_parsing_status(data):
    name = data.get('name')
    if name in parsing_processes:
        process_info = parsing_processes[name]
        is_running = process_info['process'].is_alive()
        
        emit('parsing_status_update', {
            'is_running': is_running,
            'task_id': process_info['task_id'],
            'start_time': process_info['start_time'],
            'is_full': process_info.get('is_full', False)
        })
    else:
        emit('parsing_status_update', {
            'is_running': False
        })

@socketio.on('get_stats')
def socket_get_stats():
    stats = get_competitor_stats()
    emit('stats_update', {
        'stats': stats
    })

if __name__ == '__main__':
    # Создаем папки, если их нет
    os.makedirs('templates', exist_ok=True)
    os.makedirs(DATA_FOLDER, exist_ok=True)
    
    # Запускаем приложение
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)