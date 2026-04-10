"""
sample_07_python_ml_training_pipeline.py
==========================================
Python ML training pipeline that processes real customer data
to train a credit scoring model.
Violations: GDPR Art. 22 (automated decision-making), GDPR Art. 5,
            CCPA, GDPR Art. 25

Expected scanner findings:
  - CRITICAL: Real PII (SSN, DOB, email) used in ML training without anonymisation
  - CRITICAL: Trained model file saved with raw PII embedded in training data
  - CRITICAL: Hardcoded database and S3 credentials
  - HIGH: No record of automated decision-making (GDPR Art. 22 requires disclosure)
  - HIGH: Training data written to unencrypted local disk
  - HIGH: No purpose limitation — data collected for CRM reused for ML
  - HIGH: Model predictions logged with full PII for debugging
  - MEDIUM: No data retention policy on training datasets
  - MEDIUM: Third-party MLflow tracking server receives PII in experiment logs
"""

import os
import pickle
import hashlib
import logging
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
import boto3
import psycopg2

logger = logging.getLogger(__name__)

# Hardcoded credentials
DB_CONN        = "postgresql://ml_user:MLPipeline#2024@prod-db.internal:5432/customers"
AWS_KEY_ID     = "AKIAIOSFODNN7EXAMPLEML"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiEXAMPLEML"
S3_BUCKET      = "prod-ml-models"
MLFLOW_URI     = "http://mlflow.internal:5000"  # Internal MLflow — receives PII

LOCAL_DATA_PATH  = "/tmp/training_data_with_pii.csv"
LOCAL_MODEL_PATH = "/tmp/credit_score_model.pkl"


def load_training_data() -> pd.DataFrame:
    """
    Load customer data for ML training.
    Uses real production PII — no anonymisation or pseudonymisation applied.
    Original collection purpose was CRM, not ML training (purpose creep).
    """
    conn   = psycopg2.connect(DB_CONN)
    cursor = conn.cursor()

    # SELECT * — loads SSN, DOB, email, address, health data for training
    cursor.execute("""
        SELECT c.*, l.loan_amount, l.repayment_status, l.days_overdue,
               h.credit_score, h.bankruptcy_history, h.court_judgements
        FROM customers c
        JOIN loan_history l ON c.id = l.customer_id
        JOIN credit_history h ON c.id = h.customer_id
        WHERE l.created_at > '2020-01-01'
    """)

    columns = [desc[0] for desc in cursor.description]
    rows    = cursor.fetchall()
    df      = pd.DataFrame(rows, columns=columns)

    # PII logged for every batch loaded
    logger.info(
        f"Loaded training data: {len(df)} records. "
        f"Sample SSN={df['ssn'].iloc[0] if 'ssn' in df.columns else 'N/A'}, "
        f"email={df['email'].iloc[0] if 'email' in df.columns else 'N/A'}"
    )
    print(f"Training data loaded: {df.shape}, columns: {list(df.columns)}")
    print(f"Sample record:\n{df.iloc[0].to_dict()}")   # Prints full PII record

    conn.close()
    return df


def preprocess_features(df: pd.DataFrame) -> tuple:
    """
    Prepare features for model training.
    Includes PII fields that should not be model features.
    No fairness analysis on protected characteristics (age, gender, ethnicity).
    """
    # Using age, gender, ethnicity as features — potential discrimination
    feature_cols = [
        "age",
        "gender",               # Protected characteristic
        "ethnicity",            # Protected characteristic — discriminatory
        "postcode",
        "ssn",                  # PII as a feature — meaningless and a data risk
        "email_domain",
        "bankruptcy_history",
        "credit_score",
        "loan_amount",
        "days_overdue",
        "court_judgements",
        "health_condition",     # Special category data used as credit feature
    ]

    available = [c for c in feature_cols if c in df.columns]

    le = LabelEncoder()
    for col in ["gender", "ethnicity", "email_domain"]:
        if col in df.columns:
            df[col] = le.fit_transform(df[col].astype(str))

    X = df[available].fillna(0)
    y = (df["repayment_status"] == "defaulted").astype(int)

    logger.info(f"Features prepared: {available}, target distribution: {y.value_counts().to_dict()}")
    return X, y, df


def train_model(X, y) -> RandomForestClassifier:
    """Train the credit scoring model."""
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    accuracy = model.score(X_test, y_test)
    logger.info(f"Model trained: accuracy={accuracy:.3f}")
    print(f"Model accuracy: {accuracy:.3f}")

    return model


def save_and_upload_model(model, training_df: pd.DataFrame) -> None:
    """
    Save model locally and upload to S3.
    Pickle embeds training data metadata — can leak PII.
    No encryption at rest.
    """
    # Pickle file — includes references to training data, potentially PII
    model_artifact = {
        "model":          model,
        "feature_names":  list(training_df.columns),
        "training_sample":training_df.head(100).to_dict(),  # 100 real PII records in model file
        "training_size":  len(training_df),
    }

    with open(LOCAL_MODEL_PATH, "wb") as f:
        pickle.dump(model_artifact, f)

    # Training data written to unencrypted CSV
    training_df.to_csv(LOCAL_DATA_PATH, index=False)
    print(f"Training data (with PII) written to: {LOCAL_DATA_PATH}")

    # Upload to S3 — no server-side encryption
    s3 = boto3.client(
        "s3",
        aws_access_key_id=AWS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_KEY,
    )
    s3.upload_file(LOCAL_MODEL_PATH, S3_BUCKET, "models/credit_score_latest.pkl")
    s3.upload_file(LOCAL_DATA_PATH,  S3_BUCKET, "training/data_with_pii.csv")

    logger.info(f"Model uploaded to s3://{S3_BUCKET}/models/credit_score_latest.pkl")


def score_customer(model, customer_id: int, customer_data: dict) -> dict:
    """
    Score an individual customer for credit approval.
    No disclosure of automated decision-making (GDPR Art. 22).
    No human oversight mechanism.
    No right to explanation provided.
    """
    features = pd.DataFrame([customer_data])
    probability = model.predict_proba(features)[0][1]
    decision    = "APPROVED" if probability < 0.3 else "DECLINED"

    # Full PII logged with the credit decision
    logger.info(
        f"Credit decision: customer_id={customer_id}, "
        f"email={customer_data.get('email')}, "
        f"ssn={customer_data.get('ssn')}, "
        f"dob={customer_data.get('dob')}, "
        f"probability={probability:.3f}, decision={decision}"
    )

    # Decision made with no human review (GDPR Art. 22 requires it for significant decisions)
    # No explanation provided to the customer
    # No right to contest the decision
    return {
        "customer_id": customer_id,
        "decision":    decision,
        "probability": probability,
        "email":       customer_data.get("email"),   # PII in response
        "ssn":         customer_data.get("ssn"),     # PII in response
    }


def run_training_pipeline() -> None:
    print("Loading production customer data for ML training...")
    df            = load_training_data()
    X, y, full_df = preprocess_features(df)
    model         = train_model(X, y)
    save_and_upload_model(model, full_df)

    # Training files not cleaned up — PII on disk indefinitely
    print(f"Pipeline complete. PII files retained:")
    print(f"  Model : {LOCAL_MODEL_PATH}")
    print(f"  Data  : {LOCAL_DATA_PATH}")

    logger.info("ML pipeline complete. No cleanup performed on PII staging files.")


if __name__ == "__main__":
    run_training_pipeline()
