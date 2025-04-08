#!/usr/bin/env python3
import argparse
import subprocess
import os
import sys

def run_parser(competitor=None, limit=None):
    """Запускает скрипт парсинга с указанными параметрами"""
    script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'competitor_parser.py')
    
    command = [sys.executable, script_path]
    
    if competitor:
        command.extend(['--competitor', competitor])
    
    if limit:
        command.extend(['--limit', str(limit)])
    
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        
        print("Вывод скрипта:")
        print(stdout.decode('utf-8'))
        
        if stderr:
            print("Ошибки:")
            print(stderr.decode('utf-8'))
        
        if process.returncode == 0:
            print("Парсинг успешно завершен")
        else:
            print(f"Ошибка при выполнении парсинга. Код возврата: {process.returncode}")
    
    except Exception as e:
        print(f"Ошибка при запуске скрипта: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Запуск парсера конкурентов')
    parser.add_argument('--competitor', help='Имя конкурента для парсинга')
    parser.add_argument('--limit', type=int, help='Ограничение количества статей для парсинга')
    
    args = parser.parse_args()
    
    run_parser(args.competitor, args.limit)