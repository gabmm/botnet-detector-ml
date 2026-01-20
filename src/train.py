from pathlib import Path
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from features import prepare_features


BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_DIR = BASE_DIR / "model"
MODEL_PATH = MODEL_DIR / "botnet_rf.pkl"


def train():
    X, y, removed_features = prepare_features()

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=10,
        stratify=y # esse parametro garante que a quantidade de BOT / BENIGN vai ficar igual pros dois set (train/test)
    )

    # 3. Criar o modelo
    model = RandomForestClassifier(
        n_estimators=100,
        random_state=10,
        class_weight="balanced",
        n_jobs=-1
    )

    # 4. Treinar
    model.fit(X_train, y_train)

    # 5. Salvar o modelo
    MODEL_DIR.mkdir(exist_ok=True)
    joblib.dump(model, MODEL_PATH)

    print("Modelo treinado e salvo em:", MODEL_PATH)
    print("Features removidas:", len(removed_features))
    print("Instâncias de treino:", X_train.shape[0])
    print("Instâncias de teste:", X_test.shape[0])


if __name__ == "__main__":
    train()
