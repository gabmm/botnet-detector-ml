import pandas as pd
import numpy as np
from pathlib import Path

#aqui estou normalizando o filepath
BASE_DIR = Path(__file__).resolve().parent.parent
DATASET_PATH = BASE_DIR / "data" / "set.csv"
REPORT_PATH = BASE_DIR / "report" / "set_report.md"

df = pd.read_csv(DATASET_PATH)

# avaliação do dataset

n_rows, n_cols = df.shape
df.columns = df.columns.str.strip() # trimm no nome das colunas
label_counts = df["Label"].value_counts()
label_percentage = df["Label"].value_counts(normalize=True) * 100
df["Label_num"] = df["Label"].apply(lambda x: 0 if x == "BENIGN" else 1) # converte coluna string para numero (é a unica desse dataset)
nan_counts = df.isna().sum() # conta quantas vazios por coluna
total_nan = nan_counts.sum()
inf_counts = np.isinf(df.select_dtypes(include=[np.number])).sum() # conta quantos infinitos por coluna
total_inf = inf_counts.sum()

# avaliar quais colunas tem dados constantes, logo são inúteis e não devem entrar no modelo
constant_cols = [
    col for col in df.columns
    if df[col].nunique() <= 1
]


# Criaçao do relatório
REPORT_PATH.parent.mkdir(exist_ok=True)

with open(REPORT_PATH, "w", encoding="utf-8") as f:
    f.write("# Relatório do dataset - Detector de BOTNET \n\n")
    f.write("## GERAL\n")
    f.write(f"- Número de instâncias (linhas): **{n_rows}**\n")
    f.write(f"- Número de atributos (colunas): **{n_cols}**\n\n")
    f.write("## LABELS\n")
    for label in label_counts.index:
        f.write(f"- {label}: {label_counts[label]} "
                f"(**{label_percentage[label]:.2f}%**)\n")
    f.write("\n")
    f.write("## DADOS\n")
    f.write(f"- Total de valores brancos (NaN): **{total_nan}**\n")
    f.write(f"- Total de valores infinitos (Inf): **{total_inf}**\n\n")

    f.write("## ATRIBUTOS CONSTANTES\n")
    f.write(f"### Número de colunas constantes: **{len(constant_cols)}**\n")
    if constant_cols:
        for col in constant_cols:
            f.write(f"- {col}\n")
    else:
        f.write("- Nenhuma\n")

# limpar nulos e infs
print("Limpando infs e nans...")
df.replace([np.inf, -np.inf], np.nan, inplace=True)
n_rows_before = df.shape[0]
df.dropna(inplace=True)
n_rows_after = df.shape[0]
rows_total_removed = n_rows_before - n_rows_after

label_percentage_after = df["Label"].value_counts(normalize=True) * 100
counts_after = df["Label"].value_counts()
diff_bot = label_percentage_after["Bot"] - label_percentage["Bot"]
diff_benign = label_percentage_after["BENIGN"] - label_percentage["BENIGN"]

with open(REPORT_PATH, "a", encoding="utf-8") as f:
    f.write("\n")
    f.write("## LIMPEZA DE NaN e Inf\n\n")
    f.write(f"- Número de linhas removidas: {rows_total_removed} "
            f"(**{(rows_total_removed / n_rows_before) * 100:.2f}%**)\n\n")
    for label in counts_after.index:
        f.write(f"- {label}: {counts_after[label]} "
                f"(**{label_percentage_after[label]:.2f}%**)\n"
                f"- Removidos: {label_counts[label] - counts_after[label]}\n\n")
    f.write(f"- Variação BENIGN: {diff_benign:.4f}%\n")
    f.write(f"- Variação BOT: {diff_bot:.4f}%\n")
    
print("Relatório gerado em:", REPORT_PATH)

# testagem final
assert not df.isna().any().any()
assert not np.isinf(df.select_dtypes(include=[np.number])).any().any()