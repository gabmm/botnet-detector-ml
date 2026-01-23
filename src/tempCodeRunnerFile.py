from pathlib import Path
import joblib

import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay
)

from features import prepare_features


BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_PATH = BASE_DIR / "model" / "botnet_rf.pkl"


def evaluate():
    X, y, _ = prepare_features()

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=10,
        stratify=y
    )

    model = joblib.load(MODEL_PATH)

    y_pred = model.predict(X_test)

    print("\n=== Classification Report ===\n")
    print(classification_report(
        y_test,
        y_pred,
        target_names=["BENIGN", "BOT"]
    ))

    cm = confusion_matrix(y_test, y_pred)
    disp = ConfusionMatrixDisplay(
        confusion_matrix=cm,
        display_labels=["BENIGN", "BOT"]
    )

    disp.plot(cmap="Blues")
    plt.title("Confusion Matrix – Botnet Detection")
    plt.show()


if __name__ == "__main__":
    evaluate()
