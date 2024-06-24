import os
import torch
import torch.nn as nn
import torch.optim as optim
import joblib
import numpy as np
import spacy
import warnings
from sklearn.ensemble import RandomForestClassifier

# Отключение предупреждений spacy
warnings.filterwarnings("ignore", message=r"\[W095\]", category=UserWarning)

# Загрузка модели SpaCy для обработки текста
nlp = spacy.load("ru_core_news_md")

# Нейросеть
class BiLSTMClassifier(nn.Module):
    def __init__(self, input_dim, hidden_dim, num_classes, num_layers):
        super(BiLSTMClassifier, self).__init__()
        # Инициализация двунаправленной LSTM
        self.lstm = nn.LSTM(input_dim, hidden_dim, num_layers, batch_first=True, bidirectional=True)
        # Удваиваем размер скрытого слоя, т.к. данные будут идти в двух направлениях
        self.fc = nn.Linear(hidden_dim * 2, num_classes)  # Полносвязный слой для классификации
        
    def forward(self, x):
        # Прямое распространение через LSTM
        lstm_out, (hn, cn) = self.lstm(x)
        # Конкатенируем последние скрытые состояния с обоих направлений
        hn_cat = torch.cat((hn[-2], hn[-1]), dim=1)
        return self.fc(hn_cat)  # Возвращаем результат последнего скрытого состояния

# Параметры модели
input_dim = 300
hidden_dim = 256
num_classes = 2
num_layers = 2
num_epochs = 10
batch_size = 27
learning_rate = 0.0009

# Параметры устройства
device = torch.device('cpu' if not torch.cuda.is_available() else 'cuda')

# Загрузка обученной модели
model = BiLSTMClassifier(input_dim, hidden_dim, num_classes, num_layers).to(device)
criterion = nn.CrossEntropyLoss()
optimizer = optim.Adam(model.parameters(), lr=learning_rate)

model_path = f"models/BI_LSTM_model.pth"
checkpoint = torch.load(model_path, map_location=device)
model.load_state_dict(checkpoint['model_state_dict'])
optimizer.load_state_dict(checkpoint['optimizer_state_dict'])
model.to(device)
model.eval()

# Токенизация и лемматизация текста
def tokenize_text(text):
    doc = nlp(text)
    return [token.lemma_ for token in doc if token.is_alpha]

# Преобразование токенов в векторы и проверка наличия вектора для каждого токена
def vectorize_text(tokens):
    vectors = [nlp.vocab[token].vector for token in tokens if nlp.vocab[token].has_vector]
    if vectors:  # Проверка на пустоту списка для избежания ошибок при создании массива
        vectors = np.array(vectors)
        return torch.tensor(vectors, dtype=torch.float32)
    else:
        # Возвращаем пустой тензор с правильной формой, если векторов не найдено
        return torch.empty((0, nlp.vocab.vectors_length), dtype=torch.float32)

def prepare_text_for_prediction(text):
    # Токенизация и лемматизация текста
    tokens = tokenize_text(text)
    
    # Векторизация токенов
    vectorized_text = vectorize_text(tokens)
    
    # Проверка на пустоту тензора (если нет векторов)
    if vectorized_text.nelement() == 0:
        return torch.empty((1, 0, nlp.vocab.vectors_length))

    return vectorized_text.unsqueeze(0)

# Словарь классов
class_names = {0: "Легитимное", 1: "Фишинг"}

# Подготовка текста для предсказания
def predict(text):
    try:
        prepared_data = prepare_text_for_prediction(text)
        if (prepared_data.shape[1] == 0):
            return "Недостаточно данных для анализа нейросетью", None
        with torch.inference_mode():
            output = model(prepared_data.to(device))
            predicted_probabilities = torch.softmax(output, dim=1)
            predicted_class = torch.argmax(predicted_probabilities, dim=1)
            predicted_class_name = class_names[predicted_class.item()]
            probabilities_str = ", ".join(f"{prob:.2f}" for prob in predicted_probabilities.numpy().flatten())
        return predicted_class_name, probabilities_str
    except Exception as e:
        return "Ошибка предсказания", None

# Загрузка модели классификатора RandomForest из файла
model_forest = joblib.load('models/RandomForestClassifier_model.joblib')

# Прогнозирование с использованием RandomForest
def rand_forest_pred(prob_phish_int, malicious_url_count, malicious_file_count):
    try:
        data = np.array([[prob_phish_int, malicious_url_count, malicious_file_count]])
        random_forest_predict = model_forest.predict(data)
        return "Фишинг" if random_forest_predict[0] == 1 else "Легитимное"
    except Exception as e:
        return "Ошибка предсказания"
