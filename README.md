# Botnet Detection com Machine Learning

Este projeto implementa um classificador de tráfego de rede capaz de identificar
fluxos benignos e fluxos oriundos de botnets, utilizando aprendizado de máquina
supervisionado.

O objetivo é acadêmico, no contexto da disciplina de Segurança da Informação.

### Discentes:
- Gabriel Martins da Costa Medeiros - 201935032
- Giovanni Almeida - 202465035AC
- Guilherme Roldão dos Reis Pimenta - 202435001
- Lucas Duarte Chaves - 202176012


---

## 📊 Dataset

O projeto utiliza um subconjunto do **CIC-IDS 2017**, amplamente utilizado em
pesquisas de detecção de intrusão.

O dataset **não está incluído neste repositório**.

Coloque o arquivo em:

```
data/set.csv
```

---

## 🧠 Metodologia

- Análise exploratória dos dados (EDA)
- Limpeza de valores NaN e infinitos
- Remoção de features constantes
- Classificação supervisionada
- Modelo utilizado: **Random Forest**
- Tratamento de desbalanceamento com `class_weight="balanced"`

---

## ⚙️ Requisitos

- Python **3.10+**

Bibliotecas utilizadas:

```
pandas
numpy
scikit-learn
joblib
matplotlib
```

Instalação:

```bash
pip install -r requirements.txt
```

---

## ▶️ Como executar

### 1️⃣ Análise exploratória
```bash
python src/eda.py
```

Observe o relatório gerado em /report

### 2️⃣ Treinar o modelo
```bash
python src/train.py
```

### 3️⃣ Avaliar o modelo
```bash
python src/evaluate.py
```
---

## Próximos passos
- Experimentar outros modelos
- Testar outros datasets
- Explicar resultados no relatório