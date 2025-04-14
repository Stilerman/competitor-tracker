# utils.py
import random
import pandas as pd
from datetime import datetime
import locale # Импортируем locale для доступа к установленной локали

# Импортируем константы и настройки из config.py
from config import (
    USER_AGENTS,
    PROXIES,
    DATETIME_DISPLAY_FORMAT,
    DATE_DISPLAY_FORMAT,
    log # Импортируем настроенный логгер
)

def get_random_headers() -> dict:
    """Генерирует случайные заголовки для HTTP-запроса."""
    if not USER_AGENTS:
        log.warning("Список USER_AGENTS пуст. Запросы будут идти без User-Agent.")
        return {}
    user_agent = random.choice(USER_AGENTS)
    # Формируем стандартные заголовки, имитирующие браузер
    headers = {
        'User-Agent': user_agent,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
        'Accept-Encoding': 'gzip, deflate, br', # Запрос сжатия
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'same-origin', # или 'none', если переходы с других сайтов
        'Sec-Fetch-User': '?1',
        # Добавляем заголовки для имитации более реалистичного браузера (опционально)
        # 'Sec-Ch-Ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        # 'Sec-Ch-Ua-Mobile': '?0',
        # 'Sec-Ch-Ua-Platform': '"Windows"', # Или "macOS", "Linux" и т.д.
        'Cache-Control': 'max-age=0',
        'TE': 'Trailers', # Transfer Encoding (редко используется, но бывает)
    }
    return headers

def get_proxy() -> dict | None:
    """Возвращает случайный прокси из списка PROXIES."""
    if PROXIES:
        return random.choice(PROXIES)
    return None

def _format_date_safe(date_obj, display_format) -> str:
    """Безопасно форматирует дату, обрабатывая ошибки и None/NaT."""
    if pd.isna(date_obj) or date_obj is None:
        return "N/A" # Возвращаем "Not Available" или пустую строку
    try:
        # Если пришла строка, пытаемся её распарсить сначала
        if isinstance(date_obj, str):
            parsed_date = pd.to_datetime(date_obj, errors='coerce')
            if pd.isna(parsed_date):
                 log.debug(f"Не удалось распарсить строку как дату: '{date_obj}'")
                 return "Invalid Date" # Или str(date_obj)
            date_obj = parsed_date

        # Проверяем, что это объект datetime перед форматированием
        if isinstance(date_obj, datetime):
            # Используем установленную локаль для имен месяцев/дней (%B)
            return date_obj.strftime(display_format)
        else:
             log.warning(f"Попытка форматировать не-datetime объект: {type(date_obj)}, значение: {date_obj}")
             return str(date_obj) # Возвращаем строковое представление как fallback

    except ValueError as e: # Ошибка форматирования (например, год вне диапазона)
        log.warning(f"Ошибка форматирования даты '{date_obj}' с форматом '{display_format}': {e}")
        return "Invalid Date"
    except Exception as e: # Другие неожиданные ошибки
        log.exception(f"Неожиданная ошибка при форматировании даты '{date_obj}': {e}")
        return "Error"

def format_datetime_display(date_obj) -> str:
    """Форматирует дату и время для отображения пользователю."""
    return _format_date_safe(date_obj, DATETIME_DISPLAY_FORMAT)

def format_date_display(date_obj) -> str:
    """Форматирует только дату для отображения пользователю."""
    return _format_date_safe(date_obj, DATE_DISPLAY_FORMAT)

log.debug("Модуль utils инициализирован.")