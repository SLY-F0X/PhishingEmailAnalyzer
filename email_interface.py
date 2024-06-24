import customtkinter as ctk
from tkinter import (
    messagebox,
    Listbox,
    StringVar,
    BooleanVar,
    Scrollbar,
    Menu,
    Checkbutton,
    IntVar,
    filedialog,
)
from tkinter.ttk import Combobox, Style
import email
import email_logic as logic
import imaplib
import vt_url_analize as url_check
import vt_file_scan as file_scan
import json
import os
from concurrent.futures import ThreadPoolExecutor
import time
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# Глобальные переменные для сохранения состояния
global api_key
api_key = "3647c32478b3aac2a668c93b4b56d412d37dcf2167def28a165409f8170cf4a8"
client = None
email_ids = []

current_subject = None
current_body = None
current_just_URLS = None
current_links = None
last_selected_folder = ""
malicious_url_count: int = 0
malicious_file_count: int = 0

SERVERS = {
    "Rambler": "imap.rambler.ru",
    "Yandex": "imap.yandex.ru",
    "Mail.ru": "imap.mail.ru",
    "Ввести вручную": "Custom",
}

CONFIG_FILE = "config.json"
executor = ThreadPoolExecutor(max_workers=4)


def save_config(
    email,
    password,
    retry_enabled=True,
    retries=2,
    delay=5,
    api_key="",
    last_selected_folder=""
):
    """Функция для сохранения конфигурации в файл config.json"""
    config = {
        "email": email,
        "password": password,
        "retry_enabled": retry_enabled,
        "retries": int(retries),
        "delay": int(delay),
        "api_key": api_key,
        "last_selected_folder": last_selected_folder
    }
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f)


def load_config():
    """Функция для загрузки конфигурации из файла config.json"""
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            config = json.load(f)
            config["retry_enabled"] = config.get("retry_enabled", True)
            config["retries"] = int(config.get("retries", 2))
            config["delay"] = int(config.get("delay", 5))
            config["api_key"] = config.get("api_key", "")
            config["last_selected_folder"] = config.get("last_selected_folder", "")
            return config
    return None


def connect_to_server_with_retry(server, email_address, password, retries, delay):
    """Функция для подключения к серверу с попытками повтора"""
    global client, last_selected_folder
    for attempt in range(int(retries)):
        try:
            client = logic.connect_to_server(server, email_address, password)
            if last_selected_folder:
                logic.search_emails(client, last_selected_folder)
            return client
        except Exception as e:
            if attempt < int(retries) - 1:
                time.sleep(int(delay))
                messagebox.showinfo(
                    "Внимание!",
                    f"Попытка повторного подключения {attempt + 1}/{retries}",
                )
            else:
                try:
                    client = imaplib.IMAP4_SSL(server)
                    client.login(email_address, password)
                    if last_selected_folder:
                        logic.search_emails(client, last_selected_folder)
                    return client
                except Exception as ssl_error:
                    messagebox.showerror(
                        "Ошибка соединения",
                        f"Не удалось подключиться после {retries} попыток, включая IMAP4_SSL",
                    )
                    raise ssl_error


def on_fetch_emails():
    """Функция для получения писем после подключения к серверу"""
    global client
    server_name = server_var.get()
    server = SERVERS[server_name] if server_name != "Custom" else custom_server_entry.get()
    email_address = email_entry.get()
    password = password_entry.get()

    if not server or not email_address or not password:
        messagebox.showerror("Ошибка получения писем", "Заполните все поля!")
        return

    try:
        if retry_var.get():
            client = connect_to_server_with_retry(
                server,
                email_address,
                password,
                retries_var.get(),
                delay_var.get(),
            )
        else:
            client = logic.connect_to_server(server, email_address, password)

        folder_names = logic.list_folders(client)

        folder_listbox.delete(0, "end")
        for idx, folder_name in enumerate(folder_names, 1):
            folder_listbox.insert("end", f"{idx}. {folder_name}")

        # Автоматически выбираем последнюю выбранную папку
        if last_selected_folder:
            for i, folder_name in enumerate(folder_names):
                if folder_name == last_selected_folder:
                    folder_listbox.selection_set(i)
                    folder_listbox.see(i)
                    break

        if remember_var.get():
            save_config(
                email_address,
                password,
                retry_var.get(),
                retries_var.get(),
                delay_var.get(),
                api_key_var.get(),
                last_selected_folder,
            )
    except Exception as e:
        messagebox.showerror("Ошибка получения писем", str(e))


def async_search_emails(folder, progress_bar, progress_label, progress_frame):
    """Асинхронная функция для поиска писем в выбранной папке"""
    global email_ids, last_selected_folder
    last_selected_folder = folder

    if remember_var.get():
        save_config(
            email_entry.get(),
            password_entry.get(),
            retry_var.get(),
            retries_var.get(),
            delay_var.get(),
            api_key_var.get(),
            last_selected_folder,
        )
    try:
        email_ids = logic.search_emails(client, folder)
        email_headers = []
        for idx, e_id in enumerate(email_ids, 1):
            subject, from_address, envelope_from = logic.fetch_email_headers(client, e_id)
            email_headers.append(f"{idx}. {subject}")

        # Обновляем email_listbox в основном потоке
        app.after(0, update_email_listbox, email_headers)
    except Exception as e:
        # app.after(0, show_error, str(e))
        app.after(0, lambda: on_fetch_emails())
    finally:
        app.after(0, lambda: progress_bar.stop())
        app.after(0, lambda: progress_frame.grid_remove())


def update_email_listbox(email_headers):
    """Обновление списка писем в интерфейсе"""
    email_listbox.delete(0, "end")
    for header in email_headers:
        email_listbox.insert("end", header)

def show_error(message):
    """Отображение ошибки в интерфейсе"""
    messagebox.showerror("Ошибка", message)


def on_select_folder():
    """Обработка выбора папки с письмами"""
    global last_selected_folder
    try:
        selected_indices = folder_listbox.curselection()
        selected_index = selected_indices[0]
        selected_folder = folder_listbox.get(selected_index).split(". ", 1)[1]
        last_selected_folder = selected_folder

        # Создание и отображение прогресс-бара
        progress_frame = ctk.CTkFrame(right_frame)
        progress_frame.grid(row=3, column=0, columnspan=2, pady=5, sticky="ew")

        progress_label = ctk.CTkLabel(progress_frame, text="Загрузка писем...")
        progress_label.pack(side="left", padx=10)

        progress_bar = ctk.CTkProgressBar(progress_frame, mode="indeterminate")
        progress_bar.pack(side="left", fill="x", expand=True, padx=10)
        progress_bar.start()

        executor.submit(
            async_search_emails,
            selected_folder,
            progress_bar,
            progress_label,
            progress_frame,
        )
    except IndexError:
        messagebox.showerror("Ошибка", "Выберите папку с письмами!")
    except Exception as e:
        app.after(0, lambda: on_fetch_emails())
        messagebox.showerror("Ошибка загрузки папок с письмами", str(e))


def async_fetch_email(email_id, progress_bar, progress_label, progress_frame):
    """Асинхронная функция для получения содержимого письма"""
    global current_subject, current_body, current_just_URLS, current_links
    try:
        msg = logic.fetch_email(client, email_id)
        from_address = email.utils.parseaddr(msg["From"])[1]
        to_address = email.utils.parseaddr(msg["To"])[1]
        subject = msg["Subject"] or "(Без темы)"
        decoded_subject = email.header.make_header(email.header.decode_header(subject))
        email_body, links_text, just_URLS = logic.get_email_body(msg)
        attachments_info = logic.extract_attachments_info(msg)
        envelope_from = logic.extract_envelope_from(msg.get("Received"))

        # Сохраняем для дальнейшего использования
        current_subject = str(decoded_subject)
        current_body = str(email_body)
        current_just_URLS = just_URLS
        current_links = links_text

        # Открываем окно просмотра письма в основном потоке
        app.after(
            0,
            show_email_window,
            from_address,
            envelope_from,
            to_address,
            decoded_subject,
            email_body,
            links_text,
            just_URLS,
            attachments_info,
            bool(attachments_info),
            msg,
        )
    except Exception as e:
        app.after(0, lambda: on_fetch_emails())
    finally:
        app.after(0, lambda: progress_bar.stop())
        app.after(0, lambda: progress_frame.grid_remove())


def on_select_email():
    """Обработка выбора письма из списка"""
    global selected_email_id
    try:
        selected_indices = email_listbox.curselection()
        if not selected_indices:
            raise IndexError("Письмо не выбрано")
        selected_index = selected_indices[0]
        selected_email_id = email_ids[selected_index]

        # Создание и отображение прогресс-бара
        progress_frame = ctk.CTkFrame(right_frame)
        progress_frame.grid(row=3, column=0, columnspan=2, pady=5, sticky="ew")

        progress_label = ctk.CTkLabel(progress_frame, text="Загрузка письма...")
        progress_label.pack(side="left", padx=10)

        progress_bar = ctk.CTkProgressBar(progress_frame, mode="determinate")
        progress_bar.pack(side="left", fill="x", expand=True, padx=10)
        progress_bar.start()

        executor.submit(
            async_fetch_email,
            selected_email_id,
            progress_bar,
            progress_label,
            progress_frame,
        )
    except IndexError:
        messagebox.showerror("Ошибка", "Выберите письмо!")
    except Exception as e:
        app.after(0, lambda: on_fetch_emails())
        messagebox.showerror("Ошибка при выборе письма", str(e))

# Импорт нейросети и случайного леса для анализа писем
def import_neural_network():
    global NeuralNetwork
    import predict_BI_LSTM as NeuralNetwork


def move_phish():
    try:
        logic.move_email_to_filtered_phishing(client, selected_email_id.decode('utf-8'))
        app.after(0, lambda: messagebox.showinfo("Результат", "Письмо перемещено в папку FilteredPhishing"))
        app.after(0, lambda: update_email_listbox_after_filter(last_selected_folder))
    except Exception as e:
        app.after(0, lambda: messagebox.showerror("Ошибка", f"Не удалось переместить письмо: {str(e)}"))

def show_email_window(
    from_address,
    envelope_from,
    to_address,
    subject,
    body,
    links,
    just_URLS,
    attachments,
    has_attachments,
    msg,
):
    """Отображение окна просмотра письма"""
    if not app.winfo_exists():
        return
    email_window = ctk.CTkToplevel(app)
    email_window.title("Просмотр письма")
    email_window.geometry("800x600")
    email_window.lift()
    email_window.focus_force()
    email_window.grab_set()

    from_label = ctk.CTkLabel(email_window, text=f"Отправитель: {from_address}")
    from_label.pack(padx=10, pady=1, anchor="w")

    envelope_from_label = ctk.CTkLabel(
        email_window, text=f"Cлужебный адрес отправителя: {envelope_from}"
    )
    envelope_from_label.pack(padx=10, pady=1, anchor="w")

    to_label = ctk.CTkLabel(email_window, text=f"Кому: {to_address}")
    to_label.pack(padx=10, pady=1, anchor="w")

    subject_label = ctk.CTkLabel(email_window, text=f"Тема: {subject}")
    subject_label.pack(padx=10, pady=1, anchor="w")

    tabs = ctk.CTkTabview(email_window)
    tabs.pack(expand=True, fill="both", padx=10, pady=0)

    text_tab = tabs.add("Текст")
    links_tab = tabs.add("Текст URL")
    url_tab = tabs.add("Ссылки")
    attachments_tab = tabs.add("Приложения")

    body_text = ctk.CTkTextbox(text_tab, wrap="word")
    body_text.pack(expand=True, fill="both", padx=10, pady=0)
    body_text.insert("end", body)
    body_text.configure(state="disabled")

    links_text = ctk.CTkTextbox(links_tab, wrap="word")
    links_text.pack(expand=True, fill="both", padx=10, pady=0)
    links_text.insert("end", links)
    links_text.configure(state="disabled")

    url_frame = ctk.CTkFrame(url_tab)
    url_frame.pack(expand=True, fill="both", padx=10, pady=0)

    scrollbar = Scrollbar(url_frame)
    scrollbar.pack(side="right", fill="y")

    url_canvas = ctk.CTkCanvas(url_frame, yscrollcommand=scrollbar.set)
    url_canvas.pack(side="left", fill="both", expand=True)

    scrollbar.config(command=url_canvas.yview)

    url_container = ctk.CTkFrame(url_canvas)
    url_canvas.create_window((0, 0), window=url_container, anchor="nw")

    url_vars = []
    for url in just_URLS:
        url_text = url if len(url) <= 280 else url[:279] + "..."
        var = IntVar()
        chk = Checkbutton(url_container, text=url_text, variable=var)
        chk.pack(anchor="w")
        url_vars.append((url, var))

    url_container.update_idletasks()
    url_canvas.config(scrollregion=url_canvas.bbox("all"))

    attachments_text = ctk.CTkTextbox(attachments_tab, wrap="word")
    attachments_text.pack(expand=True, fill="both", padx=10, pady=0)
    attachments_text.insert("end", "\n".join(attachments))
    attachments_text.configure(state="disabled")

    # Разрешаем копирование
    def enable_copy(event):
        body_text.configure(state="normal")
        body_text.event_generate("<<Copy>>")
        body_text.configure(state="disabled")

        links_text.configure(state="normal")
        links_text.event_generate("<<Copy>>")
        links_text.configure(state="disabled")

    # Привязка клавиши Ctrl+C для копирования
    body_text.bind("<Control-c>", enable_copy)
    links_text.bind("<Control-c>", enable_copy)

    # Создание контекстного меню
    def make_context_menu(widget):
        context_menu = Menu(widget, tearoff=0)
        context_menu.add_command(label="Копировать", command=lambda: enable_copy(None))
        return context_menu

    body_text.bind(
        "<Button-3>",
        lambda event: make_context_menu(body_text).tk_popup(event.x_root, event.y_root),
    )
    links_text.bind(
        "<Button-3>",
        lambda event: make_context_menu(links_text).tk_popup(event.x_root, event.y_root),
    )

    def analyze_selected_links(just_URLS, url_vars):
        """Анализ выбранных ссылок"""
        global malicious_url_count
        num_links = len(just_URLS)

        if num_links == 0:
            messagebox.showinfo("Анализ ссылок", "Нет ссылок для анализа.")
            return 0

        elif num_links == 1:
            selected_links = just_URLS
        else:
            selected_links = [url for url, var in url_vars if var.get() == 1]
            if not selected_links:
                messagebox.showwarning(
                    "Предупреждение", "Выберите хотя бы одну ссылку для анализа!"
                )
                tabs.set("Ссылки")  # Переключение на вкладку "Ссылки"
                return

        progress_window = ctk.CTkToplevel(app)
        progress_window.title("Анализ ссылок")
        progress_window.geometry("290x260")
        progress_window.lift()
        progress_window.focus_force()
        progress_window.grab_set()

        progress_label = ctk.CTkLabel(
            progress_window, text="Обработка ссылок...", font=("Arial", 14)
        )
        progress_label.pack(pady=10)

        progress_bar = ctk.CTkProgressBar(progress_window, mode="determinate")
        progress_bar.pack(pady=10, padx=20, fill="x")
        progress_bar.set(0)

        result_label = ctk.CTkLabel(progress_window, text="", font=("Arial", 12))
        result_label.pack(pady=10)

        result_texts = []

        # Выполнение анализа ссылок на Virustotal
        def perform_URL_results():
            global malicious_url_count
            for index, link in enumerate(selected_links):
                result, malicious_counts = url_check.analyze_and_save_url_report(link, api_key)
                result_texts.append(f"{result}")

                # Обновление интерфейса в главном потоке
                app.after(0, lambda: progress_bar.set((index + 1) / len(selected_links)))
                app.after(
                    0,
                    lambda: progress_label.configure(
                        text=f"Обработка ссылки {index + 1} из {len(selected_links)}"
                    ),
                )
                app.after(0, lambda: result_label.configure(text="\n".join(result_texts)))

                try:
                    malicious_url_count += int(malicious_counts)
                except ValueError:
                    messagebox.showerror(
                        "Ошибка", f"Не удалось преобразовать число угроз: {malicious_counts}"
                    )

            app.after(0, progress_window.destroy)
            app.after(0, lambda: messagebox.showinfo("Результат анализа", "\n".join(result_texts)))

        executor.submit(perform_URL_results)

    def select_file_for_analysis():
        """Выбор файла для анализа"""
        progress_window = ctk.CTkToplevel(app)
        progress_window.title("Анализ файлов")
        progress_window.geometry("290x260")
        progress_window.lift()
        progress_window.focus_force()
        progress_window.grab_set()

        progress_label = ctk.CTkLabel(
            progress_window, text="Обработка файлов...", font=("Arial", 14)
        )
        progress_label.pack(pady=10)

        progress_bar = ctk.CTkProgressBar(progress_window, mode="determinate")
        progress_bar.pack(pady=10, padx=20, fill="x")
        progress_bar.set(0)

        result_label = ctk.CTkLabel(progress_window, text="", font=("Arial", 12))
        result_label.pack(pady=10)

        file_result = []

        # Выполнение анализа файлов
        def perform_file_analysis(file_paths):
            global malicious_file_count
            for index, file_path in enumerate(file_paths):
                result_message, malicious_counts = file_scan.analyze_file(file_path, api_key)
                file_result.append(f"{result_message}")

                app.after(0, lambda: progress_bar.set((index + 1) / len(file_paths)))
                app.after(
                    0,
                    lambda: progress_label.configure(
                        text=f"Обработка файла {index + 1} из {len(file_paths)}"
                    ),
                )
                app.after(0, lambda: result_label.configure(text="\n".join(file_result)))

                try:
                    malicious_file_count += int(malicious_counts)
                except ValueError:
                    app.after(
                        0,
                        lambda: messagebox.showerror(
                            "Ошибка", f"Не удалось преобразовать число угроз: {malicious_counts}"
                        ),
                    )

            app.after(0, progress_window.destroy)
            app.after(0, lambda: messagebox.showinfo("Результат анализа", "\n".join(file_result)))

        file_paths = filedialog.askopenfilenames(
            initialdir="attachments/", title="Выберите файлы для анализа"
        )

        if file_paths:
            executor.submit(perform_file_analysis, file_paths)
        else:
            app.after(0, progress_window.destroy)
            messagebox.showwarning("Предупреждение", "Файлы не выбраны")

    def download_attachments():
        """Загрузка вложений для анализа"""

        def download_and_analyze():
            try:
                logic.download_attachments(msg)
                time.sleep(2)
                app.after(0, select_file_for_analysis)
            except Exception as e:
                app.after(0, messagebox.showerror("Ошибка", str(e)))

        executor.submit(download_and_analyze)

    # Создаем кнопку "Загрузить приложения для анализа", если есть приложения
    if has_attachments:
        download_button = ctk.CTkButton(
            email_window,
            text="Загрузить приложения для анализа",
            command=download_attachments,
        )
        download_button.pack(padx=10, pady=10, side="left", expand=True, anchor="center")

    def analyze_email():
        if not app.winfo_exists():
            return
        analysis_window = ctk.CTkToplevel(app)
        analysis_window.title("Анализ письма")
        analysis_window.geometry("805x305")
        analysis_window.lift()
        analysis_window.focus_force()
        analysis_window.grab_set()

        combined_text = current_subject + " " + current_body

        def perform_neuralnetwork_analysis():
            # Отложенная загрузка модуля нейросети
            try:
                future_import_nn.result()
            except Exception as e:
                messagebox.showerror("Ошибка загрузки нейросети", str(e))

            # Вызов функции предсказания
            result, prob_str = NeuralNetwork.predict(combined_text)

            # Выполнение в основном потоке после завершения предсказания
            app.after(0, update_analysis_result, NeuralNetwork, result, prob_str)

        # Вызываем анализ в отдельном потоке
        executor.submit(perform_neuralnetwork_analysis)

        def update_analysis_result(NeuralNetwork, result, prob_str):
            """Обновление результатов анализа"""
            global malicious_url_count
            global malicious_file_count

            if not analysis_window.winfo_exists():
                return
            try:
                probabilities = list(map(float, prob_str.split(",")))
                prob_phish_int = probabilities[1] * 100
            except AttributeError as e:
                return None

            rand_forest_predict = NeuralNetwork.rand_forest_pred(
                prob_phish_int, malicious_url_count, malicious_file_count)

            # Перемещение письма в папку FilteredPhishing, если результат случайного леса фишинг
            if rand_forest_predict == "Фишинг":
                executor.submit(move_phish)

            # Создаем диаграмму
            fig, ax = plt.subplots(figsize=(3, 2))
            fig.patch.set_facecolor("#F2F2F2")
            ax.set_facecolor("#F2F2F2")
            labels = ["Легитимное", "Фишинг"]
            colors = ["#6b90d9", "#8f0018"]
            ax.pie(
                probabilities,
                labels=labels,
                colors=colors,
                autopct="%1.1f%%",
                shadow=True,
                explode=(0.1, 0),
                startangle=90,
                textprops={"weight": "bold"},
            )
            ax.axis("equal")

            chart_frame = ctk.CTkFrame(analysis_window)
            chart_frame.pack(side="left", fill="both", expand=True, padx=10, pady=10)

            chart_label = ctk.CTkLabel(
                chart_frame,
                text="Результат анализа нейросетью",
                font=("Arial", 16, "bold"),
            )
            chart_label.pack(fill="both", pady=10)

            canvas = FigureCanvasTkAgg(fig, master=chart_frame)
            canvas.draw()
            canvas.get_tk_widget().pack(fill="both", expand=True, padx=10, pady=10)

            statistics_frame = ctk.CTkFrame(analysis_window)
            statistics_frame.pack(side="right", fill="both", expand=True, padx=10, pady=10)

            analysis_result_label = ctk.CTkLabel(
                statistics_frame, text="Статистика", font=("Arial", 16, "bold")
            )
            analysis_result_label.pack(fill="both", pady=10)

            analysis_text_label = ctk.CTkLabel(
                statistics_frame, text=f"Результат анализа текста: {result}", font=("Arial", 14)
            )
            analysis_text_label.pack(padx=20, pady=5, anchor="w")

            num_links_label = ctk.CTkLabel(
                statistics_frame,
                text=f"Количество ссылок: {len(current_just_URLS)}",
                font=("Arial", 14),
            )
            num_links_label.pack(padx=20, pady=5, anchor="w")

            vt_url_analize_label = ctk.CTkLabel(
                statistics_frame,
                text=f"Количество найденных угроз в ссылках: {malicious_url_count}",
                font=("Arial", 14),
            )
            vt_url_analize_label.pack(padx=20, pady=5, anchor="w")

            vt_file_scan_label = ctk.CTkLabel(
                statistics_frame,
                text=f"Количество найденных угроз в приложениях: {malicious_file_count}",
                font=("Arial", 14),
            )
            vt_file_scan_label.pack(padx=20, pady=5, anchor="w")

            overall_results_label = ctk.CTkLabel(
                statistics_frame,
                text=f"Общий итог обработки методом случайного леса: {rand_forest_predict}",
                font=("Arial", 14),
            )
            overall_results_label.pack(padx=20, pady=5, anchor="w")

            # Сохранение данных
            logic.save_email_data(current_subject, current_body, current_links)
             
        # Cбрасывает значения глобальных переменных при закрытии окна анализа письма
        def reset_counts():
            global malicious_url_count
            global malicious_file_count
            malicious_url_count = 0
            malicious_file_count = 0
        analysis_window.protocol("WM_DELETE_WINDOW", lambda: (reset_counts(), analysis_window.destroy()))

    # Создаем кнопку "Анализировать выбранные ссылки"
    analyze_links_button = ctk.CTkButton(
        email_window,
        text="Анализировать выбранные ссылки",
        command=lambda: analyze_selected_links(just_URLS, url_vars),
    )
    analyze_links_button.pack(padx=10, pady=10, side="left", expand=True, anchor="w")

    # Создаем кнопку "Проанализировать и отфильтровать письмо"
    analyze_button = ctk.CTkButton(email_window, text="Проанализировать и отфильтровать письмо", command=analyze_email)
    analyze_button.pack(padx=10, pady=10, side="left", expand=True, anchor="e")

def update_email_listbox_after_filter(folder):
    """Обновление списка писем в интерфейсе после фильтрации"""
    global email_ids
    try:
        email_ids = logic.search_emails(client, folder)
        email_headers = []
        for idx, e_id in enumerate(email_ids, 1):
            subject, from_address, envelope_from = logic.fetch_email_headers(client, e_id.decode('utf-8'))
            email_headers.append(f"{idx}. {subject}")

        # Обновляем email_listbox в основном потоке
        app.after(0, update_email_listbox, email_headers)
    except Exception as e:
        app.after(0, lambda: on_fetch_emails())
        app.after(0, show_error, str(e))


def async_filter_phishing_emails(folder, progress_bar, progress_label, progress_frame):
    """Асинхронная функция для фильтрации фишинговых писем"""
    try:
        phishing_count = logic.filter_phishing_emails(client, folder)
        app.after(0, lambda: messagebox.showinfo(
            "Результат", 
            f"Фильтрация фишинговых писем завершена успешно!\n"
            f"Найдено фишинговых писем: {phishing_count}\n"
            f"Письма будут перемещены в папку FilteredPhishing\n"))
        app.after(0, update_email_listbox_after_filter, folder)
        app.after(0, lambda: on_fetch_emails())
    except Exception as e:
        app.after(0, lambda: on_fetch_emails())
        app.after(0, show_error, str(e))
    finally:
        app.after(0, lambda: progress_bar.stop())
        app.after(0, lambda: progress_frame.grid_remove())

def on_filter_phishing_emails():
    """Обработка нажатия кнопки фильтрации фишинговых писем"""
    global last_selected_folder
    try:
        selected_indices = folder_listbox.curselection()
        if not selected_indices:
            raise IndexError("Папка не выбрана")
        selected_index = selected_indices[0]
        selected_folder = folder_listbox.get(selected_index).split(". ", 1)[1]
        last_selected_folder = selected_folder

        # Создание и отображение прогресс-бара
        progress_frame = ctk.CTkFrame(right_frame)
        progress_frame.grid(row=3, column=0, columnspan=2, pady=5, sticky="ew")

        progress_label = ctk.CTkLabel(progress_frame, text="Фильтрация фишинговых писем...")
        progress_label.pack(side="left", padx=10)

        progress_bar = ctk.CTkProgressBar(progress_frame, mode="determinate")
        progress_bar.pack(side="left", fill="x", expand=True, padx=10)
        progress_bar.set(0)
        progress_bar.start()

        executor.submit(
            async_filter_phishing_emails,
            selected_folder,
            progress_bar,
            progress_label,
            progress_frame,
        )
        app.after(0, lambda: on_fetch_emails())
    except IndexError:
        messagebox.showerror("Ошибка", "Выберите папку с письмами!")
    except Exception as e:
        messagebox.showerror("Ошибка фильтрации фишинговых писем", str(e))

# Обработка выбора сервера для IMAP
def on_server_selection(event):
    if server_var.get() == "Ввести вручную":
        custom_server_entry.grid(row=2, column=0, padx=10, pady=5, sticky="ew")
    else:
        custom_server_entry.grid_remove()

# Показать или скрыть пароль
def toggle_password():
    if password_entry.cget("show") == "":
        password_entry.configure(show="*")
        show_password_button.configure(text="Показать пароль")
    else:
        password_entry.configure(show="")
        show_password_button.configure(text="Скрыть пароль")

# Переключение темы интерфейса
def toggle_theme():
    if theme_var.get() == "light":
        ctk.set_appearance_mode("light")
    else:
        ctk.set_appearance_mode("dark")

# Открытие окна настроек
def open_settings():
    settings_window = ctk.CTkToplevel(app)
    settings_window.title("Настройки")
    settings_window.geometry("400x250")
    settings_window.lift()
    settings_window.focus_force()
    settings_window.grab_set()

    settings_frame = ctk.CTkFrame(settings_window)
    settings_frame.pack(expand=True, fill="both", padx=10, pady=10)

    retry_label = ctk.CTkLabel(settings_frame, text="Повторные попытки подключения")
    retry_label.grid(row=1, column=0, padx=10, sticky="w")

    retry_checkbox = ctk.CTkCheckBox(settings_frame, text="", variable=retry_var, width=40)
    retry_checkbox.grid(row=1, column=1, padx=15, sticky="w")

    retries_label = ctk.CTkLabel(settings_frame, text="Количество попыток")
    retries_label.grid(row=2, column=0, padx=10, sticky="w", pady=5)

    retries_spinbox = ctk.CTkEntry(
        settings_frame, justify="center", textvariable=retries_var, width=40
    )
    retries_spinbox.grid(row=2, column=1, sticky="w", padx=10, pady=5)

    delay_label = ctk.CTkLabel(settings_frame, text="Задержка между попытками (сек)")
    delay_label.grid(row=3, column=0, sticky="w", padx=10, pady=5)

    delay_spinbox = ctk.CTkEntry(settings_frame, justify="center", textvariable=delay_var, width=40)
    delay_spinbox.grid(row=3, column=1, sticky="w", padx=10, pady=5)

    api_key_label = ctk.CTkLabel(settings_frame, text="VT API Key:")
    api_key_label.grid(row=4, column=0, sticky="w", padx=10, pady=0)

    api_key_entry = ctk.CTkEntry(
        settings_frame, justify="center", textvariable=api_key_var, width=350
    )
    api_key_entry.grid(row=5, column=0, columnspan=2, sticky="w", padx=10, pady=5)

    save_button = ctk.CTkButton(
        settings_frame,
        text="Сохранить настройки",
        command=lambda: save_config(
            email_entry.get(),
            password_entry.get(),
            retry_var.get(),
            retries_var.get(),
            delay_var.get(),
            api_key_var.get(),
            last_selected_folder,
        ),
    )
    save_button.grid(row=6, column=0, columnspan=2, pady=20)

# Настройки стиля и расположения элементов интерфейса
app = ctk.CTk()
ctk.set_default_color_theme("dark-blue")
ctk.set_appearance_mode("light")
app.title("Анализатор фишинговых сообщений")
app.geometry("800x600")

style = Style(app)
style.theme_use("vista")
style.configure("TCombobox", fieldbackground="white", background="white")

font_set = ctk.CTkFont(size=12, weight="bold")

left_frame = ctk.CTkFrame(app)
left_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ns")

ctk.CTkLabel(left_frame, text="IMAP Сервер", font=font_set).grid(
    row=0, column=0, padx=10, pady=1, sticky="w"
)
server_var = StringVar()
server_combobox = Combobox(left_frame, textvariable=server_var, state="readonly", style="TCombobox")
server_combobox["values"] = list(SERVERS.keys())
server_combobox.grid(row=1, column=0, padx=10, pady=3, sticky="ew")
server_combobox.set("Rambler")
server_combobox.bind("<<ComboboxSelected>>", on_server_selection)

custom_server_entry = ctk.CTkEntry(left_frame)
custom_server_entry.grid(row=2, column=0, padx=10, pady=5, sticky="ew")
custom_server_entry.grid_remove()

ctk.CTkLabel(left_frame, text="Адрес электронной почты", font=font_set).grid(
    row=3, column=0, padx=10, pady=1, sticky="w"
)
email_entry = ctk.CTkEntry(left_frame)
email_entry.grid(row=4, column=0, padx=10, pady=1, sticky="ew")

ctk.CTkLabel(left_frame, text="Пароль", font=font_set).grid(
    row=5, column=0, padx=10, pady=1, sticky="w"
)
password_entry = ctk.CTkEntry(left_frame, show="*")
password_entry.grid(row=6, column=0, padx=10, pady=1, sticky="ew")

show_password_button = ctk.CTkButton(left_frame, text="Показать пароль", command=toggle_password)
show_password_button.grid(row=7, column=0, padx=10, pady=5, sticky="ew")

remember_var = BooleanVar()
remember_checkbox = ctk.CTkCheckBox(left_frame, text="Запомнить меня", variable=remember_var)
remember_checkbox.grid(row=8, column=0, padx=10, pady=5, sticky="ew")

fetch_button = ctk.CTkButton(left_frame, text="Войти", command=on_fetch_emails)
fetch_button.grid(row=9, column=0, padx=10, pady=10, sticky="ew")

folder_listbox_frame = ctk.CTkFrame(left_frame)
folder_listbox_frame.grid(row=10, column=0, padx=10, pady=5, sticky="ew")

folder_listbox = Listbox(folder_listbox_frame, height=6)
folder_listbox.pack(side="left", fill="both", expand=True)

folder_listbox_scrollbar = Scrollbar(folder_listbox_frame, orient="vertical")
folder_listbox_scrollbar.config(command=folder_listbox.yview)
folder_listbox_scrollbar.pack(side="right", fill="y")

folder_listbox.config(yscrollcommand=folder_listbox_scrollbar.set)

select_folder_button = ctk.CTkButton(left_frame, text="Выбор папки", command=on_select_folder)
select_folder_button.grid(row=11, column=0, padx=10, pady=5, sticky="ew")

theme_var = StringVar(value="light")
theme_switch = ctk.CTkSwitch(
    left_frame,
    text="Переключение темы",
    variable=theme_var,
    onvalue="light",
    offvalue="dark",
    command=toggle_theme,
)
theme_switch.grid(row=13, column=0, padx=10, pady=1, sticky="ew")

settings_button = ctk.CTkButton(left_frame, text="Настройки", command=open_settings)
settings_button.grid(row=14, column=0, padx=10, pady=5, sticky="ew")

right_frame = ctk.CTkFrame(app)
right_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")

ctk.CTkLabel(right_frame, text="Список писем", font=font_set).grid(
    row=0, column=0, padx=10, pady=3, sticky="ew")

filter_folder_button = ctk.CTkButton(right_frame, text="Анализ и фильтрация фишинговых писем\n в выбранной папке", command=on_filter_phishing_emails)
filter_folder_button.grid(row=0, column=1, padx=10, pady=5, sticky="ew")

email_listbox = Listbox(right_frame)
email_listbox.grid(row=1, column=0, columnspan=2, padx=0, pady=3, sticky="nsew")

select_email_button = ctk.CTkButton(right_frame, text="Загрузить письмо", command=on_select_email)
select_email_button.grid(row=2, column=0, columnspan=2, padx=10, pady=3, sticky="ew")

app.grid_rowconfigure(0, weight=1)
app.grid_columnconfigure(1, weight=1)
right_frame.grid_rowconfigure(1, weight=1)
right_frame.grid_columnconfigure(0, weight=1)

# Загрузка конфигурации при запуске приложения
config = load_config()
# Если конфигурация загружена, заполняем поля формы значениями из конфигурации
if config:
    email_entry.insert(0, config["email"])
    password_entry.insert(0, config["password"])
    retry_var = BooleanVar(value=config.get("retry_enabled", True))
    retries_var = StringVar(value=str(config["retries"]))
    delay_var = StringVar(value=str(config["delay"]))
    api_key_var = StringVar(value=config.get("api_key", ""))
    last_selected_folder = config.get("last_selected_folder", "")
    remember_var.set(True)
# Если конфигурация не загружена, устанавливаем значения по умолчанию
else:
    remember_var.set(True)
    retry_var = BooleanVar(value=True)
    retries_var = StringVar(value="2")
    delay_var = StringVar(value="5")
    api_key_var = StringVar(value="")

def on_closing():
    """Функция для обработки закрытия основного окна"""
    executor.shutdown(wait=False)  # Остановить выполнение фоновых задач
    # Закрыть все открытые окна
    for window in app.winfo_children():
        window.destroy()
    app.destroy()  # Закрыть главное окно и завершить программу
    os._exit(0)
app.protocol("WM_DELETE_WINDOW", on_closing)

# Импортируем модуль нейросети в отдельном потоке
future_import_nn = executor.submit(import_neural_network)

# Запускаем главный цикл приложения
app.mainloop()
