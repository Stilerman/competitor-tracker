# config.py
import logging
import os
import locale
from dotenv import load_dotenv

# --- Загрузка переменных окружения ---
load_dotenv() # Загружает переменные из файла .env в корне проекта

# --- Основные Настройки ---
APP_NAME = "Competitor Tracker"
DATA_FOLDER = 'data'
CONFIG_FILE = 'competitors.json'
USERS_FILE = 'users.json'
LOG_FILE = 'parser.log'
ARTICLES_PER_PAGE = 20 # Для пагинации на странице статистики

# --- Форматы Дат ---
# Формат для отображения пользователю (с учетом локали)
DATETIME_DISPLAY_FORMAT = '%d %B %Y %H:%M:%S' # Пример: 25 декабря 2023 15:30:00
DATE_DISPLAY_FORMAT = '%d %B %Y'          # Пример: 25 декабря 2023
# Формат для сохранения в CSV/JSON (ISO-подобный для совместимости и сортировки)
DATETIME_DB_FORMAT = '%Y-%m-%d %H:%M:%S'
DATE_DB_FORMAT = '%Y-%m-%d'

# --- Настройки Парсера ---
# Список User-Agent для ротации
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1.2 Mobile/15E148 Safari/604.1'
]

# Список прокси для ротации (оставьте пустым, если не используется)
# Формат: {'http': 'http://user:pass@host:port', 'https': 'https://user:pass@host:port'}
PROXIES = [
    # {'http': 'http://...', 'https': 'https://...'},
]

REQUEST_TIMEOUT = 25  # Таймаут для HTTP запросов в секундах
REQUEST_RETRIES = 3   # Количество попыток при ошибках сети/сервера
RETRY_DELAY = 3       # Базовая задержка между попытками в секундах (будет случайная до * 2)

# --- Секретный ключ Flask ---
FLASK_SECRET_KEY = os.environ.get('FLASK_SECRET_KEY')

# --- Настройка Логирования ---
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
# Убедимся, что директория для логов существует
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format=LOG_FORMAT,
    encoding='utf-8',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        logging.StreamHandler() # Вывод в консоль
    ]
)
# Уменьшаем шум от библиотек requests и urllib3
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)
# Логгер для приложения
log = logging.getLogger(APP_NAME) # Используем имя приложения для логгера

# --- Проверка секретного ключа ---
if not FLASK_SECRET_KEY:
    log.critical("!!! КРИТИЧЕСКАЯ ОШИБКА: Переменная окружения FLASK_SECRET_KEY не установлена! Задайте ее в файле .env. Приложение не будет работать безопасно. !!!")
    # В реальном продакшене можно даже остановить запуск:
    # raise ValueError("FLASK_SECRET_KEY не установлена!")
    # Для разработки можно оставить небезопасный ключ, но с громким предупреждением:
    FLASK_SECRET_KEY = 'dev-unsafe-default-key-CHANGE-ME'
    log.warning("!!! Используется НЕБЕЗОПАСНЫЙ ключ Flask по умолчанию. Сгенерируйте и установите FLASK_SECRET_KEY в .env !!!")


# --- Настройка Локализации для Дат ---
# Попытка установить русскую локаль для форматирования дат ('%B')
try:
    # Для Linux/Mac с поддержкой UTF-8
    locale.setlocale(locale.LC_TIME, 'ru_RU.UTF-8')
    log.info("Установлена локаль ru_RU.UTF-8 для форматирования дат.")
except locale.Error:
    try:
        # Для Windows
        locale.setlocale(locale.LC_TIME, 'Russian_Russia.1251')
        log.info("Установлена локаль Russian_Russia.1251 для форматирования дат.")
    except locale.Error:
        try:
             # Иногда на Windows может быть 'rus_rus'
             locale.setlocale(locale.LC_TIME, 'rus_rus')
             log.info("Установлена локаль rus_rus для форматирования дат.")
        except locale.Error:
            log.warning("Не удалось установить русскую локаль (ru_RU.UTF-8, Russian_Russia.1251 или rus_rus). Даты будут форматироваться с использованием системной локали по умолчанию (могут быть английские названия месяцев).")
            # Можно установить английскую локаль как fallback, чтобы гарантировать предсказуемый формат
            try:
                locale.setlocale(locale.LC_TIME, 'en_US.UTF-8')
            except:
                try:
                     locale.setlocale(locale.LC_TIME, 'English_United States.1252')
                except:
                     pass # Оставляем системную по умолчанию

# --- Создание папок ---
os.makedirs(DATA_FOLDER, exist_ok=True)
os.makedirs('templates', exist_ok=True) # Папка для шаблонов Flask

log.info(f"Инициализация {APP_NAME} завершена. Папка данных: {DATA_FOLDER}")