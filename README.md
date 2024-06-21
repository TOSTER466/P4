# Сервис шифрования
Этот проект представляет собой простой веб-сервис на базе Flask, который предоставляет функции шифрования и дешифрования с использованием методов шифрования Виженера и Цезаря. Включает базовое управление пользователями, обработку сессий шифрования и REST API.

Возможности
- Добавление и просмотр пользователей
- Просмотр методов шифрования
- Шифрование и дешифрование данных выбранными методами
- Просмотр и удаление сессий шифрования

Требования
- Python 3.x
- Flask
Установка
1. Клонируйте репозиторий:
````bash
git clone https://github.com/yourusername/encryption-service-api.git
cd encryption-service-api
````
2. Создайте виртуальное окружение и активируйте его:
````bash
python3 -m venv venv
source venv/bin/activate
````
3. Установите необходимые пакеты:
````bash
pip install flask
````
Использование
1. Запустите приложение Flask:
````bash
python app.py
````
2. Откройте веб-браузер и перейдите по адресу http://127.0.0.1:5000, чтобы получить доступ к веб-интерфейсу.

Методы

Шифр Виженера

- ID: 1
- Параметры: {"key": "secret_key"}
- Описание: Шифрует данные с использованием шифра Виженера
  
Шифр Цезаря

- ID: 2
- Параметры: {"shift": 3}
- Описание: Шифрует данные с использованием шифра Цезаря

Пример

Шифрование данных с использованием шифра Виженера
1. Перейдите по адресу http://127.0.0.1:5000.
2. Выберите "Vigenere Cipher" в качестве метода шифрования.
3. Введите данные для шифрования и ключ.
4. Отправьте форму для получения зашифрованных данных.
   
Удаление сессии
1. Перейдите на страницу результата сессии шифрования.
2. Введите секрет пользователя, создавшего сессию.
3. Отправьте форму для удаления сессии. Появится сообщение, подтверждающее успешное удаление сессии или сообщающее об ошибке при неправильном пароле.
