#!/usr/bin/env python3
"""
FatSecret API Food Entries Script (3-Legged OAuth)
Скрипт для получения записей о еде из FatSecret API с использованием 3-Legged OAuth аутентификации.
Позволяет получать пользовательские данные из FatSecret аккаунтов.
"""

import argparse
import json
import requests
import hmac
import hashlib
import base64
import urllib.parse
from datetime import datetime, date
import sys
import os
import time
import secrets
import webbrowser

class FatSecretOAuth:
    """Класс для работы с FatSecret Platform API через 3-Legged OAuth 1.0"""

    def __init__(self, consumer_key, consumer_secret):
        self.consumer_key = consumer_key
        self.consumer_secret = consumer_secret

        # OAuth URLs - разные для токенов и API
        self.request_token_url = "https://authentication.fatsecret.com/oauth/request_token"
        self.authorize_url = "https://authentication.fatsecret.com/oauth/authorize"
        self.access_token_url = "https://authentication.fatsecret.com/oauth/access_token"
        self.api_base_url = "https://platform.fatsecret.com/rest/server.api"

        # Токены для 3-legged OAuth
        self.request_token = None
        self.request_token_secret = None
        self.access_token = None
        self.access_token_secret = None

    def generate_nonce(self):
        """Генерировать случайный nonce"""
        return secrets.token_hex(16)

    def generate_timestamp(self):
        """Генерировать timestamp"""
        return str(int(time.time()))

    def percent_encode(self, text):
        """URL кодирование по RFC 3986"""
        return urllib.parse.quote(str(text), safe='')

    def create_signature_base_string(self, method, url, params):
        """Создать базовую строку для подписи OAuth"""
        # Сортируем параметры
        sorted_params = sorted(params.items())

        # Кодируем параметры
        encoded_params = []
        for key, value in sorted_params:
            encoded_params.append(f"{self.percent_encode(key)}={self.percent_encode(value)}")

        # Объединяем параметры
        param_string = "&".join(encoded_params)

        # Создаем базовую строку
        base_string = f"{method.upper()}&{self.percent_encode(url)}&{self.percent_encode(param_string)}"
        return base_string

    def create_signature(self, method, url, params, token_secret=""):
        """Создать HMAC-SHA1 подпись"""
        base_string = self.create_signature_base_string(method, url, params)

        # Создаем ключ для подписи
        signing_key = f"{self.percent_encode(self.consumer_secret)}&{self.percent_encode(token_secret)}"

        # Создаем подпись
        signature = hmac.new(
            signing_key.encode('utf-8'),
            base_string.encode('utf-8'),
            hashlib.sha1
        ).digest()

        return base64.b64encode(signature).decode('utf-8')

    def step1_get_request_token(self, callback_url="oob"):
        """Шаг 1: Получить request token"""
        print("🔑 Шаг 1: Получение request token...")

        # OAuth параметры для request token
        oauth_params = {
            'oauth_consumer_key': self.consumer_key,
            'oauth_nonce': self.generate_nonce(),
            'oauth_signature_method': 'HMAC-SHA1',
            'oauth_timestamp': self.generate_timestamp(),
            'oauth_version': '1.0',
            'oauth_callback': callback_url
        }

        # Создаем подпись
        signature = self.create_signature('POST', self.request_token_url, oauth_params)
        oauth_params['oauth_signature'] = signature

        # Делаем запрос
        try:
            response = requests.post(self.request_token_url, data=oauth_params)
            response.raise_for_status()

            # Парсим ответ
            response_data = urllib.parse.parse_qs(response.text)

            self.request_token = response_data['oauth_token'][0]
            self.request_token_secret = response_data['oauth_token_secret'][0]
            callback_confirmed = response_data.get('oauth_callback_confirmed', ['false'])[0]

            print(f"✅ Request token получен: {self.request_token[:10]}...")
            print(f"✅ Callback confirmed: {callback_confirmed}")

            return True

        except requests.exceptions.RequestException as e:
            print(f"❌ Ошибка при получении request token: {e}")
            if hasattr(e, 'response') and e.response:
                print(f"Ответ сервера: {e.response.text}")
            return False

    def step2_authorize_user(self, auto_open=True):
        """Шаг 2: Авторизация пользователя"""
        if not self.request_token:
            print("❌ Request token не найден. Сначала выполните шаг 1.")
            return None

        print("\n🌐 Шаг 2: Авторизация пользователя...")

        # Создаем URL для авторизации
        auth_url = f"{self.authorize_url}?oauth_token={self.request_token}"

        print(f"\n📋 Откройте следующий URL в браузере для авторизации:")
        print(f"🔗 {auth_url}")

        if auto_open:
            try:
                print("\n🚀 Пытаемся открыть браузер автоматически...")
                webbrowser.open(auth_url)
            except Exception as e:
                print(f"⚠️  Не удалось открыть браузер: {e}")

        print("\n📝 После авторизации вы получите код подтверждения (PIN).")
        verifier = input("🔢 Введите код подтверждения: ").strip()

        return verifier

    def step3_get_access_token(self, verifier):
        """Шаг 3: Получить access token"""
        if not self.request_token or not self.request_token_secret:
            print("❌ Request token не найден. Сначала выполните шаги 1-2.")
            return False

        print("\n🔐 Шаг 3: Получение access token...")

        # OAuth параметры для access token
        oauth_params = {
            'oauth_consumer_key': self.consumer_key,
            'oauth_token': self.request_token,
            'oauth_nonce': self.generate_nonce(),
            'oauth_signature_method': 'HMAC-SHA1',
            'oauth_timestamp': self.generate_timestamp(),
            'oauth_version': '1.0',
            'oauth_verifier': verifier
        }

        # Создаем подпись с request_token_secret
        signature = self.create_signature('GET', self.access_token_url, oauth_params, self.request_token_secret)
        oauth_params['oauth_signature'] = signature

        # Делаем запрос
        try:
            response = requests.get(self.access_token_url, params=oauth_params)
            response.raise_for_status()

            # Парсим ответ
            response_data = urllib.parse.parse_qs(response.text)

            self.access_token = response_data['oauth_token'][0]
            self.access_token_secret = response_data['oauth_token_secret'][0]

            print(f"✅ Access token получен: {self.access_token[:10]}...")
            print("✅ Аутентификация завершена успешно!")

            return True

        except requests.exceptions.RequestException as e:
            print(f"❌ Ошибка при получении access token: {e}")
            if hasattr(e, 'response') and e.response:
                print(f"Ответ сервера: {e.response.text}")
            return False

    def authenticate_full_flow(self, callback_url="oob", auto_open=True):
        """Выполнить полный цикл аутентификации"""
        print("🚀 Начинаем 3-Legged OAuth аутентификацию...")

        # Шаг 1: Получить request token
        if not self.step1_get_request_token(callback_url):
            return False

        # Шаг 2: Авторизация пользователя
        verifier = self.step2_authorize_user(auto_open)
        if not verifier:
            print("❌ Код подтверждения не получен.")
            return False

        # Шаг 3: Получить access token
        return self.step3_get_access_token(verifier)

    def date_to_unix_days(self, target_date):
        """Конвертировать дату в количество дней с 1 января 1970"""
        epoch = date(1970, 1, 1)
        if isinstance(target_date, str):
            target_date = datetime.strptime(target_date, '%Y-%m-%d').date()
        return (target_date - epoch).days

    def make_authenticated_request(self, method_params):
        """Сделать аутентифицированный запрос к API"""
        if not self.access_token or not self.access_token_secret:
            print("❌ Access token не найден. Сначала выполните аутентификацию.")
            return None

        # OAuth параметры для API запроса
        oauth_params = {
            'oauth_consumer_key': self.consumer_key,
            'oauth_token': self.access_token,
            'oauth_nonce': self.generate_nonce(),
            'oauth_signature_method': 'HMAC-SHA1',
            'oauth_timestamp': self.generate_timestamp(),
            'oauth_version': '1.0'
        }

        # Объединяем все параметры
        all_params = {**oauth_params, **method_params}

        # Создаем подпись с access_token_secret
        signature = self.create_signature('GET', self.api_base_url, all_params, self.access_token_secret)
        oauth_params['oauth_signature'] = signature

        # Финальные параметры для запроса
        request_params = {**oauth_params, **method_params}

        try:
            response = requests.get(self.api_base_url, params=request_params)
            response.raise_for_status()
            return response.json()

        except requests.exceptions.RequestException as e:
            print(f"❌ Ошибка при выполнении API запроса: {e}")
            if hasattr(e, 'response') and e.response:
                print(f"Ответ сервера: {e.response.text}")
            return None

    def get_food_entries(self, target_date):
        """Получить записи о еде за указанную дату"""
        date_int = self.date_to_unix_days(target_date)

        # Параметры для метода API
        method_params = {
            'method': 'food_entries.get.v2',
            'date': date_int,
            'format': 'json'
        }

        print(f"🍽️  Получение записей о еде за {target_date}...")
        return self.make_authenticated_request(method_params)

    def save_tokens(self, filename="fatsecret_tokens.json"):
        """Сохранить токены в файл"""
        if self.access_token and self.access_token_secret:
            tokens = {
                'access_token': self.access_token,
                'access_token_secret': self.access_token_secret,
                'timestamp': time.time()
            }

            try:
                with open(filename, 'w') as f:
                    json.dump(tokens, f, indent=2)
                print(f"💾 Токены сохранены в {filename}")
                return True
            except Exception as e:
                print(f"❌ Ошибка при сохранении токенов: {e}")

        return False

    def load_tokens(self, filename="fatsecret_tokens.json"):
        """Загрузить токены из файла"""
        try:
            with open(filename, 'r') as f:
                tokens = json.load(f)

            self.access_token = tokens['access_token']
            self.access_token_secret = tokens['access_token_secret']

            print(f"📁 Токены загружены из {filename}")
            return True

        except FileNotFoundError:
            print(f"⚠️  Файл токенов {filename} не найден.")
            return False
        except Exception as e:
            print(f"❌ Ошибка при загрузке токенов: {e}")
            return False

def format_food_entries_text(data):
    """Форматировать данные записей о еде в читаемый текстовый формат"""
    if not data:
        return "❌ Не удалось получить данные."

    # Проверяем на ошибки API
    if 'error' in data:
        error_info = data['error']
        return f"❌ Ошибка API: {error_info.get('message', 'Неизвестная ошибка')} (код: {error_info.get('code', 'N/A')})"

    if 'food_entries' not in data:
        return "📝 Записи о еде не найдены за указанную дату."

    entries = data['food_entries'].get('food_entry', [])
    if not isinstance(entries, list):
        entries = [entries]

    if not entries:
        return "📝 Записи о еде не найдены за указанную дату."

    result = []
    result.append(f"🍽️  Найдено записей: {len(entries)}")
    result.append("=" * 60)

    # Группируем по приемам пищи
    meals = {}
    for entry in entries:
        meal = entry.get('meal', 'other')
        if meal not in meals:
            meals[meal] = []
        meals[meal].append(entry)

    # Переводим названия приемов пищи
    meal_names = {
        'breakfast': '🌅 Завтрак',
        'lunch': '🌞 Обед', 
        'dinner': '🌙 Ужин',
        'other': '🍴 Другое'
    }

    for meal, meal_entries in meals.items():
        meal_name = meal_names.get(meal, f"🍴 {meal.title()}")
        result.append(f"\n{meal_name}:")
        result.append("-" * 40)

        total_calories = 0
        total_protein = 0
        total_fat = 0
        total_carbs = 0

        for i, entry in enumerate(meal_entries, 1):
            result.append(f"\n  {i}. {entry.get('food_entry_name', 'N/A')}")
            result.append(f"     📄 {entry.get('food_entry_description', 'N/A')}")

            calories = float(entry.get('calories', 0)) if entry.get('calories') else 0
            protein = float(entry.get('protein', 0)) if entry.get('protein') else 0
            fat = float(entry.get('fat', 0)) if entry.get('fat') else 0
            carbs = float(entry.get('carbohydrate', 0)) if entry.get('carbohydrate') else 0

            result.append(f"     🔥 {calories:.1f} ккал | 🥩 {protein:.1f}г белка | 🧈 {fat:.1f}г жира | 🍞 {carbs:.1f}г углеводов")

            total_calories += calories
            total_protein += protein
            total_fat += fat
            total_carbs += carbs

        result.append(f"\n  📊 Итого по {meal_name.lower()}:")
        result.append(f"     🔥 {total_calories:.1f} ккал | 🥩 {total_protein:.1f}г белка | 🧈 {total_fat:.1f}г жира | 🍞 {total_carbs:.1f}г углеводов")

    # Общая статистика
    grand_total_calories = sum(float(entry.get('calories', 0)) if entry.get('calories') else 0 for entry in entries)
    grand_total_protein = sum(float(entry.get('protein', 0)) if entry.get('protein') else 0 for entry in entries)
    grand_total_fat = sum(float(entry.get('fat', 0)) if entry.get('fat') else 0 for entry in entries)
    grand_total_carbs = sum(float(entry.get('carbohydrate', 0)) if entry.get('carbohydrate') else 0 for entry in entries)

    result.append(f"\n" + "=" * 60)
    result.append("📈 ОБЩАЯ СТАТИСТИКА ЗА ДЕНЬ:")
    result.append(f"🔥 {grand_total_calories:.1f} ккал | 🥩 {grand_total_protein:.1f}г белка | 🧈 {grand_total_fat:.1f}г жира | 🍞 {grand_total_carbs:.1f}г углеводов")

    return "\n".join(result)

def main():
    parser = argparse.ArgumentParser(
        description='Получить записи о еде из FatSecret API с 3-Legged OAuth аутентификацией',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  %(prog)s --date 2023-10-01 --format json
  %(prog)s --date 2023-10-01 --format text --save-tokens
  %(prog)s --load-tokens --date 2023-10-01

Переменные окружения:
  FATSECRET_CONSUMER_KEY     - Consumer Key для FatSecret API
  FATSECRET_CONSUMER_SECRET  - Consumer Secret для FatSecret API

Процесс аутентификации:
1. Скрипт откроет браузер для авторизации
2. Войдите в ваш FatSecret аккаунт  
3. Разрешите доступ приложению
4. Скопируйте код подтверждения обратно в скрипт
5. Скрипт получит данные из вашего пищевого дневника
        """)

    parser.add_argument(
        '--date', 
        default=datetime.now().strftime('%Y-%m-%d'),
        help='Дата в формате YYYY-MM-DD (по умолчанию: сегодня)'
    )

    parser.add_argument(
        '--format', 
        choices=['json', 'text'], 
        default='json',
        help='Формат вывода: json или text (по умолчанию: json)'
    )

    parser.add_argument(
        '--consumer-key',
        help='Consumer Key для FatSecret API'
    )

    parser.add_argument(
        '--consumer-secret',
        help='Consumer Secret для FatSecret API'
    )

    parser.add_argument(
        '--save-tokens',
        action='store_true',
        help='Сохранить токены в файл для повторного использования'
    )

    parser.add_argument(
        '--load-tokens',
        action='store_true',
        help='Загрузить токены из файла (пропустить аутентификацию)'
    )

    parser.add_argument(
        '--tokens-file',
        default='fatsecret_tokens.json',
        help='Файл для сохранения/загрузки токенов'
    )

    parser.add_argument(
        '--no-browser',
        action='store_true',
        help='Не открывать браузер автоматически'
    )

    args = parser.parse_args()

    # Получаем креды из аргументов или переменных окружения
    consumer_key = args.consumer_key or os.getenv('FATSECRET_CONSUMER_KEY')
    consumer_secret = args.consumer_secret or os.getenv('FATSECRET_CONSUMER_SECRET')

    if not consumer_key or not consumer_secret:
        print("❌ Ошибка: Необходимо указать Consumer Key и Consumer Secret")
        print("Используйте аргументы --consumer-key и --consumer-secret")
        print("Или установите переменные окружения FATSECRET_CONSUMER_KEY и FATSECRET_CONSUMER_SECRET")
        print("\nПолучить ключи можно на: https://platform.fatsecret.com/api/")
        sys.exit(1)

    # Валидируем формат даты
    try:
        datetime.strptime(args.date, '%Y-%m-%d')
    except ValueError:
        print(f"❌ Ошибка: Неверный формат даты '{args.date}'. Используйте формат YYYY-MM-DD")
        sys.exit(1)

    # Создаем экземпляр OAuth клиента
    oauth_client = FatSecretOAuth(consumer_key, consumer_secret)

    # Загружаем токены или выполняем аутентификацию
    if args.load_tokens:
        if not oauth_client.load_tokens(args.tokens_file):
            print("❌ Не удалось загрузить токены. Выполняем новую аутентификацию...")
            args.load_tokens = False

    if not args.load_tokens:
        # Выполняем полный цикл аутентификации
        auto_open = not args.no_browser
        if not oauth_client.authenticate_full_flow(auto_open=auto_open):
            print("❌ Аутентификация не удалась.")
            sys.exit(1)

        # Сохраняем токены если запрошено
        if args.save_tokens:
            oauth_client.save_tokens(args.tokens_file)

    # Получаем записи о еде
    food_entries = oauth_client.get_food_entries(args.date)

    if food_entries is None:
        print("❌ Не удалось получить данные из API")
        sys.exit(1)

    # Выводим результат в нужном формате
    if args.format == 'json':
        print(json.dumps(food_entries, indent=2, ensure_ascii=False))
    else:
        print(format_food_entries_text(food_entries))

if __name__ == '__main__':
    main()
