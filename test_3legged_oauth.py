#!/usr/bin/env python3
"""
Тестовый скрипт для проверки работы FatSecret 3-Legged OAuth API
"""

import os
import sys
import json
from datetime import datetime, timedelta

# Добавляем текущую директорию в путь для импорта
sys.path.insert(0, '.')

def test_credentials():
    """Проверить наличие необходимых креденциалов"""
    print("🔍 Проверка креденциалов...")

    consumer_key = os.getenv('FATSECRET_CONSUMER_KEY')
    consumer_secret = os.getenv('FATSECRET_CONSUMER_SECRET')

    if not consumer_key:
        print("❌ Переменная FATSECRET_CONSUMER_KEY не установлена")
        return False

    if not consumer_secret:
        print("❌ Переменная FATSECRET_CONSUMER_SECRET не установлена")
        return False

    print(f"✅ Consumer Key: {consumer_key[:10]}...")
    print(f"✅ Consumer Secret: {consumer_secret[:10]}...")
    return True

def test_oauth_flow():
    """Тестировать полный OAuth flow"""
    print("\n🔐 Тестирование 3-Legged OAuth flow...")

    try:
        from fatsecret_3legged_oauth import FatSecretOAuth

        consumer_key = os.getenv('FATSECRET_CONSUMER_KEY')
        consumer_secret = os.getenv('FATSECRET_CONSUMER_SECRET')

        oauth_client = FatSecretOAuth(consumer_key, consumer_secret)

        # Проверяем генерацию nonce и timestamp
        nonce = oauth_client.generate_nonce()
        timestamp = oauth_client.generate_timestamp()

        print(f"✅ Nonce генерируется: {nonce[:10]}...")
        print(f"✅ Timestamp генерируется: {timestamp}")

        # Проверяем создание подписи
        test_params = {
            'oauth_consumer_key': consumer_key,
            'oauth_nonce': nonce,
            'oauth_signature_method': 'HMAC-SHA1',
            'oauth_timestamp': timestamp,
            'oauth_version': '1.0',
            'oauth_callback': 'oob'
        }

        signature = oauth_client.create_signature('POST', oauth_client.request_token_url, test_params)
        print(f"✅ Подпись создается: {signature[:15]}...")

        print("\n⚠️  Для полного тестирования требуется интерактивная авторизация")
        print("    Запустите: python fatsecret_3legged_oauth.py --save-tokens")

        return True

    except ImportError as e:
        print(f"❌ Ошибка импорта: {e}")
        return False
    except Exception as e:
        print(f"❌ Ошибка: {e}")
        return False

def test_saved_tokens():
    """Проверить сохраненные токены"""
    print("\n💾 Проверка сохраненных токенов...")

    token_file = 'fatsecret_tokens.json'

    if not os.path.exists(token_file):
        print(f"⚠️  Файл токенов {token_file} не найден")
        print("   Выполните аутентификацию: python fatsecret_3legged_oauth.py --save-tokens")
        return False

    try:
        with open(token_file, 'r') as f:
            tokens = json.load(f)

        required_keys = ['access_token', 'access_token_secret', 'timestamp']

        for key in required_keys:
            if key not in tokens:
                print(f"❌ Отсутствует ключ '{key}' в файле токенов")
                return False

        # Проверяем возраст токенов
        token_age = datetime.now().timestamp() - tokens['timestamp']
        token_age_hours = token_age / 3600

        print(f"✅ Access token: {tokens['access_token'][:10]}...")
        print(f"✅ Access token secret: {tokens['access_token_secret'][:10]}...")
        print(f"✅ Возраст токенов: {token_age_hours:.1f} часов")

        if token_age_hours > 24 * 365:  # Больше года
            print("⚠️  Токены довольно старые, возможно стоит обновить")

        return True

    except json.JSONDecodeError:
        print(f"❌ Файл {token_file} содержит некорректный JSON")
        return False
    except Exception as e:
        print(f"❌ Ошибка при проверке токенов: {e}")
        return False

def test_api_call():
    """Тестировать API вызов с сохраненными токенами"""
    print("\n🍽️  Тестирование API вызова...")

    if not test_saved_tokens():
        return False

    try:
        from fatsecret_3legged_oauth import FatSecretOAuth

        consumer_key = os.getenv('FATSECRET_CONSUMER_KEY')
        consumer_secret = os.getenv('FATSECRET_CONSUMER_SECRET')

        oauth_client = FatSecretOAuth(consumer_key, consumer_secret)

        # Загружаем токены
        if not oauth_client.load_tokens():
            print("❌ Не удалось загрузить токены")
            return False

        # Тестируем запрос за сегодня
        today = datetime.now().strftime('%Y-%m-%d')
        print(f"📅 Тестирование получения данных за {today}...")

        food_entries = oauth_client.get_food_entries(today)

        if food_entries is None:
            print("❌ API вернул None")
            return False

        if 'error' in food_entries:
            error_info = food_entries['error']
            print(f"❌ API ошибка: {error_info.get('message', 'Неизвестная ошибка')} (код: {error_info.get('code')})")
            return False

        print("✅ API запрос выполнен успешно")

        if 'food_entries' in food_entries:
            entries = food_entries['food_entries'].get('food_entry', [])
            if not isinstance(entries, list):
                entries = [entries]
            print(f"📊 Найдено {len(entries)} записей за {today}")
        else:
            print(f"📊 Записей за {today} не найдено")

        return True

    except Exception as e:
        print(f"❌ Ошибка при тестировании API: {e}")
        return False

def run_interactive_test():
    """Запустить интерактивный тест с пошаговым выполнением"""
    print("🎯 Интерактивный тест 3-Legged OAuth")
    print("=" * 50)

    choice = input("\nВыберите действие:\n1. Новая аутентификация\n2. Тест с существующими токенами\n3. Полная проверка\nВведите номер (1-3): ").strip()

    if choice == '1':
        print("\n🚀 Запуск новой аутентификации...")
        os.system("python fatsecret_3legged_oauth.py --save-tokens --format text")

    elif choice == '2':
        if test_api_call():
            print("\n✅ Тест с существующими токенами прошел успешно!")

            # Показываем пример данных
            print("\n📋 Получение данных за вчера в текстовом формате...")
            yesterday = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')
            os.system(f"python fatsecret_3legged_oauth.py --load-tokens --date {yesterday} --format text")
        else:
            print("\n❌ Тест не прошел. Попробуйте новую аутентификацию.")

    elif choice == '3':
        print("\n🔍 Полная проверка системы...")

        tests = [
            ("Проверка креденциалов", test_credentials),
            ("Тестирование OAuth компонентов", test_oauth_flow), 
            ("Проверка сохраненных токенов", test_saved_tokens),
            ("Тестирование API вызова", test_api_call)
        ]

        results = []
        for test_name, test_func in tests:
            print(f"\n{'='*20}")
            print(f"🧪 {test_name}")
            print('='*20)
            result = test_func()
            results.append((test_name, result))

        print("\n" + "="*50)
        print("📊 РЕЗУЛЬТАТЫ ТЕСТИРОВАНИЯ")
        print("="*50)

        for test_name, result in results:
            status = "✅ ПРОШЕЛ" if result else "❌ НЕ ПРОШЕЛ"
            print(f"{status} - {test_name}")

        passed = sum(1 for _, result in results if result)
        total = len(results)
        print(f"\n🎯 Итого: {passed}/{total} тестов пройдено")

    else:
        print("❌ Неверный выбор")

def main():
    print("🧪 FatSecret 3-Legged OAuth - Тестовая утилита")
    print("=" * 60)

    # Проверяем наличие файла .env
    if os.path.exists('.env'):
        print("📄 Найден файл .env, загружаем переменные окружения...")
        try:
            with open('.env', 'r') as f:
                for line in f:
                    if '=' in line and not line.startswith('#'):
                        key, value = line.strip().split('=', 1)
                        os.environ[key] = value
            print("✅ Переменные окружения загружены")
        except Exception as e:
            print(f"⚠️  Ошибка при загрузке .env файла: {e}")

    run_interactive_test()

if __name__ == '__main__':
    main()
