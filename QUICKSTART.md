# 🚀 Быстрый старт - FatSecret 3-Legged OAuth

## ⚡ Минимальные шаги для запуска

### 1. Установка
```bash
pip install requests
```

### 2. Получение API ключей
1. Идите на https://platform.fatsecret.com/api/
2. Зарегистрируйтесь как разработчик
3. Создайте новое приложение
4. Скопируйте **Consumer Key** и **Consumer Secret**

### 3. Настройка переменных окружения
```bash
export FATSECRET_CONSUMER_KEY="ваш_consumer_key"
export FATSECRET_CONSUMER_SECRET="ваш_consumer_secret"
```

### 4. Первый запуск
```bash
python fatsecret_3legged_oauth.py --save-tokens --format text
```

Скрипт:
1. 🌐 Откроет браузер для авторизации FatSecret
2. 🔑 Попросит войти в ваш FatSecret аккаунт  
3. ✅ Попросит разрешить доступ приложению
4. 🔢 Попросит ввести код подтверждения
5. 💾 Сохранит токены для повторного использования
6. 📊 Покажет ваши записи о еде за сегодня

### 5. Повторное использование
```bash
python fatsecret_3legged_oauth.py --load-tokens --date 2023-10-01 --format text
```

## ❗ Важно

- ✅ Используйте **Consumer Key/Secret** (OAuth 1.0)
- ❌ НЕ используйте Client ID/Secret (OAuth 2.0)
- 🔐 Храните токены в безопасности
- 📱 Нужен аккаунт на FatSecret.com с записями в дневнике

## 🆘 Помощь

- `python fatsecret_3legged_oauth.py --help` - полная справка
- `python test_3legged_oauth.py` - интерактивное тестирование
- `python examples_3legged.py` - примеры использования
