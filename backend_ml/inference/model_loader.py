import os
import joblib
from xgboost import XGBClassifier

MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "models")


def load_models():
    models = {}

    models["rf"] = joblib.load(os.path.join(MODEL_DIR, "randomforest_v2.pkl"))
    models["extra"] = joblib.load(os.path.join(MODEL_DIR, "extratrees_v2.pkl"))
    models["mlp"] = joblib.load(os.path.join(MODEL_DIR, "mlp_v2.pkl"))
    models["lgbm"] = joblib.load(os.path.join(MODEL_DIR, "lightgbm_v2.pkl"))

    # XGBoost (JSON format – safe)
    xgb = XGBClassifier()
    xgb.load_model(os.path.join(MODEL_DIR, "xgboost.json"))
    models["xgb"] = xgb

    return models
