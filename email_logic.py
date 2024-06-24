import os
import email
import imaplib
import re
from bs4 import BeautifulSoup
from bs4 import Comment
import json

client = None


def fetch_email_headers(client, e_id):
    """Функция для получения заголовков письма."""
    status, response = client.fetch(e_id, "(BODY[HEADER])")
    if status != "OK":
        raise Exception("Не удалось получить заголовки письма.")
    raw_email = response[0][1]
    msg = email.message_from_bytes(raw_email)
    subject = msg["Subject"] or "(Без темы)"
    from_address = msg["From"]
    decoded_subject = email.header.make_header(email.header.decode_header(subject))
    envelope_from = extract_envelope_from(msg.get("Received"))
    return decoded_subject, from_address, envelope_from


def extract_envelope_from(received_header):
    """Извлекает envelope-from из заголовка Received."""
    if received_header:
        match = re.search(r"envelope-from\s*<([^>]+)>", received_header)
        if match:
            return match.group(1)
    return None


def clean_text(text):
    """Удаляет избыточные пробелы и переводы строк из текста."""
    # Удаляем избыточные переводы строк
    text = re.sub(r"[\r\n]+", " ", text)
    # Определяем невидимые символы по их кодам Unicode
    invisible_chars_codes = [10240, 8204, 160, 8203, 8205, 8288, 65279, 5760, 6158, 8239, 8287, 12288]
    text = ''.join(char for char in text if ord(char) not in invisible_chars_codes)
    # Удаляем избыточные пробелы
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def strip_html_tags(text):
    """Удаляет HTML теги, CSS стили и скрипты из текста и выделяет ссылки."""

    soup = BeautifulSoup(text, "html.parser")

    for script_or_style in soup(
        [
            "script",
            "style",
            "head",
            "title",
            "meta",
            "[document]",
            'link[rel="stylesheet"]',
        ]
    ):
        script_or_style.decompose()

    # Удаление атрибутов стилей margin и padding, а также изображений без содержания
    for tag in soup.find_all(True):  # True означает "любой тег"
        if "style" in tag.attrs:
            css_style = tag["style"]
            # Создаем фильтрацию CSS стилей, удаляя margin и padding
            filtered_styles = [
                style.strip()
                for style in css_style.split(";")
                if "margin" not in style and "padding" not in style
            ]
            tag["style"] = "; ".join(filtered_styles)

            # Удаляем атрибут style, если он пуст после фильтрации
            if not tag["style"]:
                del tag["style"]

    # Удаление изображений
    for img in soup.find_all("img"):
        # Проверяем является ли оно прозрачным пикселем
        if not img.get("src") or "transparent" in img.get("src"):
            img.decompose()

    for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
        comment.extract()

    links = {}
    for link in soup.find_all("a", href=True):
        href = link["href"].strip()
        text = link.get_text(strip=True)
        if href in links:
            links[href].add(text)
        else:
            links[href] = set([text])

    # Форматируем вывод ссылок
    formatted_links = []
    just_URLS = []
    for href, texts in links.items():
        for text in texts:
            if text:
                formatted_links.append(f"{text}\n{href}")
                just_URLS.append(f"{href}")
            else:
                formatted_links.append(href)
                just_URLS.append(f"{href}")
        formatted_links.append("")

    text = soup.get_text(separator=" ", strip=True)
    text = text.replace("\xa0", " ")  # Замена Unicode неразрывных пробелов на обычные пробелы
    text = text.replace("&nbsp;", " ")  # Это на случай, если неразрывные пробелы не были преобразованы
    return clean_text(text), formatted_links[:-1], just_URLS


def get_email_body(msg):
    """Извлекает и возвращает тело письма в виде текста, включая гиперссылки."""
    email_body = ""
    links = []
    just_URLS = []
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = part.get("Content-Disposition")
            if content_type.startswith("text/") and (
                content_disposition is None or "attachment" not in content_disposition
            ):
                payload = part.get_payload(decode=True)
                try:
                    part_content = payload.decode("utf-8")
                except UnicodeDecodeError:
                    part_content = payload.decode("windows-1252", errors="replace")

                # Применяем strip_html_tags для всех текстов
                text, part_links, part_just_URLS = strip_html_tags(part_content)
                email_body = clean_text(text)  # Последующая очистка текста
                links.extend(part_links)
                just_URLS.extend(part_just_URLS)
    else:
        payload = msg.get_payload(decode=True)
        try:
            part_content = payload.decode("utf-8")
        except UnicodeDecodeError:
            part_content = payload.decode("windows-1252", errors="replace")

        email_body, links, just_URLS = strip_html_tags(part_content)
        email_body = clean_text(email_body)

    if links:
        links_text = "\n".join(links)
    else:
        links_text = ""

    return email_body, links_text, just_URLS


def connect_to_server(server, email_address, password):
    """Подключение к серверу и авторизация пользователя."""
    global client
    try:
        client = imaplib.IMAP4_SSL(server)
        client.login(email_address, password)
    except Exception as e:
        raise Exception("Не удалось подключиться или войти на сервер: " + str(e))
    return client


def list_folders(client):
    """Список папок на сервере."""
    status, folder_names = client.list()
    if status != "OK":
        raise Exception("Не удалось получить список папок.")
    return [(folder.decode().split(' "/" ')[1]) for folder in folder_names]


def search_emails(client, folder):
    """Поиск писем в указанной папке."""
    client.select(folder, readonly=False)
    status, data = client.search(None, "ALL")
    if status != "OK":
        raise Exception("Не удалось выполнить поиск писем.")
    return data[0].split()


def fetch_email(client, email_id):
    """Получение письма по его идентификатору."""
    status, response = client.fetch(email_id, "(RFC822)")
    if status != "OK":
        raise Exception("Не удалось получить письмо.")
    raw_email = response[0][1]
    return email.message_from_bytes(raw_email)


def decode_attachment_filename(filename):
    """Декодирует имя файла и возвращает его в безопасном для файловой системы формате."""
    if filename is None:
        return None

    decoded_filename = str(email.header.make_header(email.header.decode_header(filename)))
    safe_filename = (
        decoded_filename.replace("\r", "")
        .replace("\n", "")
        .replace("\\", "")
        .replace("/", "")
        .replace("<", "")
        .replace(">", "")
        .replace(":", "")
        .replace('"', "")
        .replace("|", "")
        .replace("?", "")
        .replace("*", "")
    )
    return safe_filename


def extract_attachments_info(msg):
    """Извлекает информацию о приложениях из письма."""
    attachments_info = []
    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue
        if part.get("Content-Disposition") is None:
            continue
        filename = decode_attachment_filename(part.get_filename())
        if filename:
            attachments_info.append(
                f"{filename} (тип: {part.get_content_type()}, размер: {len(part.get_payload(decode=True))} байт)"
            )
    return attachments_info


def download_attachments(msg):
    """Загружает приложения из письма."""
    attachments_dir = os.path.join(os.getcwd(), "attachments")
    os.makedirs(attachments_dir, exist_ok=True)

    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue
        if part.get("Content-Disposition") is None:
            continue
        filename = decode_attachment_filename(part.get_filename())
        if filename:
            file_data = part.get_payload(decode=True)
            file_path = os.path.join(attachments_dir, filename)
            with open(file_path, "wb") as f:
                f.write(file_data)


def save_email_data(subject, body, links, txt_file=None):
    """Сохраняет данные письма в файл JSON."""
    subject = str(subject)
    body = clean_text(str(body))
    links = str(links)

    # Преобразуем список ссылок
    if isinstance(links, str):
        only_urls = links.split("\n")
        only_urls = [url.strip() for url in only_urls if url.strip()]
    elif isinstance(links, list):
        only_urls = links
    else:
        only_urls = []

    email_data = {"Subject": subject, "Body": body, "URL": only_urls}

    save_email_dir = os.path.join(os.getcwd(), "email_analyze")
    os.makedirs(save_email_dir, exist_ok=True)

    if txt_file is None:
        txt_file = "current_email_data.json"

    file_path = os.path.join(save_email_dir, txt_file)

    with open(file_path, "w", encoding="utf-8") as file:
        json.dump(email_data, file, ensure_ascii=False, indent=4)


# Фильтрация фишинговых сообщений
def filter_phishing_emails(client, folder):

    import predict_BI_LSTM as NeuralNetwork

    def get_email_ids(client, folder):
        return search_emails(client, folder)

    email_ids = get_email_ids(client, folder)
    was_phishing_found = True
    phishing_count = 0

    if folder == "FilteredPhishing":
        return "\n\nЗдесь находятся уже отфильтрованные письма\n"

    while email_ids and was_phishing_found:
        was_phishing_found = False

        for e_id in email_ids:
            # Получаем письмо по его ID
            msg = fetch_email(client, e_id)
        
            # Извлекаем тему и тело письма
            subject, from_address, envelope_from = fetch_email_headers(client, e_id)
            body, links_text, _ = get_email_body(msg)

            # Создаем текст для предсказания
            text = str(subject) + " " + str(body)
            text = clean_text(text)

            # Предсказание нейросетью
            result, prob_str = NeuralNetwork.predict(text)

            # Если результат фишинг, перемещаем письмо в новую папку
            if result == "Фишинг":
                # Проверяем наличие папки FilteredPhishing, если нет - создаем её
                status, folders = client.list()
                if status == "OK" and "FilteredPhishing" not in [folder.decode().split(' "/" ')[1] for folder in folders]:
                    client.create("FilteredPhishing")

                # Получаем список всех папок
                folder_status, folder_list = client.list()
                if folder_status != 'OK':
                    raise Exception("Не удалось получить список папок.")

                # Перемещаем письмо в папку FilteredPhishing
                move_status = client.copy(e_id, 'FilteredPhishing')
                if move_status[0] != 'OK':
                    raise Exception(f"Не удалось скопировать письмо {e_id} в папку FilteredPhishing.")

                # Удаляем письмо из исходной папки
                client.store(e_id, '+FLAGS', '\\Deleted')
                client.expunge()

                was_phishing_found = True
                phishing_count += 1
                break
        # Обновляем список email_ids после удаления
        email_ids = get_email_ids(client, folder)

    return phishing_count

def move_email_to_filtered_phishing(client, email_id):
    """Перемещаем письмо в папку FilteredPhishing."""
    status, folders = client.list()
    if status == "OK" and "FilteredPhishing" not in [folder.decode().split(' "/" ')[1] for folder in folders]:
        client.create("FilteredPhishing")

    move_status = client.copy(email_id, 'FilteredPhishing')
    if move_status[0] != 'OK':
        raise Exception(f"Не удалось скопировать письмо {email_id} в папку FilteredPhishing.")
    client.store(email_id, '+FLAGS', '\\Deleted')
    client.expunge()
