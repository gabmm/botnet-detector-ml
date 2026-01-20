from pathlib import Path
from typing import Tuple, List
import pandas as pd
import numpy as np

BASE_DIR = Path(__file__).resolve().parent.parent
DATASET_PATH = BASE_DIR / "data" / "set.csv"

def load_dataset() -> pd.DataFrame:
    df = pd.read_csv(DATASET_PATH)
    df.columns = df.columns.str.strip()
    return df


def clean_dataset(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    return df


def remove_constant_features(df: pd.DataFrame) -> Tuple[pd.DataFrame, List[str]]:
    constant_cols = [
        col for col in df.columns
        if df[col].nunique() <= 1
    ]

    df = df.drop(columns=constant_cols)

    return df, constant_cols


def prepare_features() -> Tuple[pd.DataFrame, pd.Series, List[str]]:
    df = load_dataset()
    df = clean_dataset(df)

    df["Label_num"] = df["Label"].apply(
        lambda x: 0 if x == "BENIGN" else 1
    )
    df, removed_cols = remove_constant_features(df)

    X = df.drop(columns=["Label", "Label_num"])
    y = df["Label_num"]

    return X, y, removed_cols
