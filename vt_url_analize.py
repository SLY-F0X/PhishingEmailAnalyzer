import requests
import time
import json
import os

# Функция анализа выбранной ссылки
def analyze_and_save_url_report(input_url, api_key):
    url = "https://www.virustotal.com/api/v3/urls"
    payload = {"url": input_url}
    headers = {
        "accept": "application/json",
        "x-apikey": api_key,
        "content-type": "application/x-www-form-urlencoded"
    }
    try:
        response = requests.post(url, data=payload, headers=headers)
        response.raise_for_status()
        response_json = response.json()
        analysis_id = response_json['data']['id']
    except Exception as e:
        return f"Произошла ошибка при анализе URL: {e}"

    time.sleep(3)

    for _ in range(50):
        try:
            url_report = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            response = requests.get(url_report, headers=headers)
            response.raise_for_status()
            response_json = response.json()
            
            if response_json['data']['attributes']['status'] == "completed":
                results = extract_url_report(response_json, input_url, analysis_id)
                break
        except Exception as e:
            return f"Произошла ошибка при получении отчета по URL: {e}"
        
        time.sleep(6)

    else:
        return "Анализ URL не завершен в течение ожидаемого времени."

    malicious_counts = results.get('malicious_count', 0)
    
    if results and results['malicious_count'] >= 1:
        save_results_to_file('email_analyze/vt_url_result.json', results)
        return format_results(results), int(malicious_counts)
    else:
        save_results_to_file('email_analyze/vt_url_result.json', results)
        return f"{input_url} Угроз не найдено", int(malicious_counts)

# Извлечение данных из отчета
def extract_url_report(response_json, input_url, analysis_id):
    attributes = response_json['data']['attributes']
    stats = attributes.get('stats', {})
    malicious_count = stats.get('malicious', 0)
    
    results = attributes.get('results', {})
    malicious_results = []
    for antivirus, result in results.items():
        if result['category'] == 'malicious':
            result_detail = result.get('result', 'N/A')
            malicious_results.append((antivirus, result_detail))

    report_link = f"https://www.virustotal.com/gui/file/{analysis_id}/detection"

    return {
        "input_url": input_url,
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
    input_url = results["input_url"]
    report_link = results["report_link"]

    # Форматирование результатов антивирусов
    antivirus_results = results["malicious_results"]
    formatted_antivirus_results = "\n".join([f"{av}: {detail}" for av, detail in antivirus_results])

    # Форматирование итогового сообщения
    result_message = (
        f"Ссылка: {input_url}\n"
        f"Количество найденных угроз: {malicious_count}\n"
        f"Результаты:\n{formatted_antivirus_results}\n"
        f"Ссылка на отчет: {report_link}\n"
        f"Результаты сохранены в vt_url_result.json\n"
    )

    return result_message
