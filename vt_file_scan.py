import os
import requests
import time
import json

# Функция анализа выбранного файла
def analyze_file(file_path, api_key):
    # Проверка существования файла
    if not os.path.exists(file_path):
        return f"Файл {file_path} не существует."

    # URL и заголовки для запроса к VirusTotal API
    url = 'https://www.virustotal.com/api/v3/files'
    headers = {
        'accept': 'application/json',
        'x-apikey': api_key,
    }

    try:
        # Открытие и отправка файла на анализ
        with open(file_path, 'rb') as file:
            files = {'file': file}
            response = requests.post(url, headers=headers, files=files)
            response.raise_for_status()
            response_json = response.json()
    except Exception as e:
        return f"Произошла ошибка при загрузке файла: {e}"

    # Получение ID анализируемого файла
    file_id = response_json['data']['id']

    # Ожидание перед запросом отчета
    time.sleep(3)

    # Повторные попытки получения отчета
    for _ in range(60):
        try:
            url_report = f'https://www.virustotal.com/api/v3/analyses/{file_id}'
            response = requests.get(url_report, headers=headers)
            response.raise_for_status()
            response_json = response.json()

            # Проверка статуса анализа
            if response_json['data']['attributes']['status'] == "completed":
                results = extract_file_report(response_json, file_path, file_id)
                break
        except Exception as e:
            return f"Произошла ошибка при получении отчета по файлу: {e}"

        # Ожидание перед следующей попыткой
        time.sleep(6)

    else:
        return "Анализ файла не завершен в течение ожидаемого времени."

    # Получение количества обнаруженных угроз
    malicious_counts = results.get('malicious_count', 0)

    # Сохранение и форматирование результатов
    if results and results['malicious_count'] >= 1:
        save_results_to_file('email_analyze/vt_file_results.json', results)
        return format_results(results), int(malicious_counts)
    else:
        return f"{os.path.basename(file_path)} Угроз не найдено", int(malicious_counts)

# Извлечение данных из отчета
def extract_file_report(response_json, file_path, file_id):
    attributes = response_json['data']['attributes']
    stats = attributes.get('stats', {})
    malicious_count = stats.get('malicious', 0)
    
    results = attributes.get('results', {})
    malicious_results = []
    for antivirus, result in results.items():
        if result['category'] == 'malicious':
            result_detail = result.get('result', 'N/A')
            malicious_results.append((antivirus, result_detail))

    # Ссылка на полный отчет
    report_link = f"https://www.virustotal.com/gui/file/{file_id}/detection"

    return {
        "file_name": os.path.basename(file_path),
        "report_link": report_link,
        "malicious_count": malicious_count,
        "malicious_results": malicious_results
    }

# Сохранение результатов в файл
def save_results_to_file(file_path, data):
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
        with open(file_path, 'r+') as file:
            try:
                file_data = json.load(file)
                if not isinstance(file_data, list):
                    file_data = []
            except json.JSONDecodeError:
                file_data = []
            file_data.append(data)
            file.seek(0)
            json.dump(file_data, file, indent=4)
            file.truncate()
    else:
        with open(file_path, 'w') as file:
            json.dump([data], file, indent=4)

# Форматирование результатов для отображения
def format_results(results):
    malicious_count = results["malicious_count"]
    file_name = results["file_name"]
    report_link = results["report_link"]

    # Форматирование результатов антивирусов
    antivirus_results = results["malicious_results"]
    formatted_antivirus_results = "\n".join([f"{av}: {detail}" for av, detail in antivirus_results])

    # Форматирование итогового сообщения
    result_message = (
        f"Файл: {file_name}\n"
        f"Количество найденных угроз: {malicious_count}\n"
        f"Результаты:\n{formatted_antivirus_results}\n"
        f"Ссылка на отчет: {report_link}\n"
        f"Результаты сохранены в vt_file_results.json\n"
    )

    return result_message
