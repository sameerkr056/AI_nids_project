
# AI-Powered Network Intrusion Detection System
# For Production mode (Real - world data)
import streamlit as st
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import seaborn as sns
import matplotlib.pyplot as plt

#PAGE CONFIG...
st.set_page_config(page_title="AI NIDS Dashboard", layout="wide")
st.title("AI-Based Network Intrusion Detection System")
st.write("For Production mode (Real - world data)")

# PROJECT OVERVIEW 
st.markdown("""
###  Project Overview
This project implements an **AI-powered Network Intrusion Detection System (NIDS)**  
to detect **DDoS attacks** in network traffic.

- Machine Learning Algorithm: **Random Forest**
- Classification Type: **Binary (BENIGN vs DDoS)**
- Dataset: **CIC-IDS 2017 (Friday Working Hours-DDoS)**
- Deployment: **Streamlit Dashboard**

The system analyzes network flow features and classifies traffic
as **normal (BENIGN)** or **malicious (DDoS attack)**.
""")
# SIDEBAR 
st.sidebar.header("Model Configuration")
split_size = st.sidebar.slider("Training Data (%)", 50, 90, 80)
n_estimators = st.sidebar.slider("Number of Trees", 10, 200, 100)

# LOAD DATA 
@st.cache_data
def load_data():
    # Dataset is uploaded locally and path is hardcoded
    path = "C:/Users/ASUS/Desktop/nids project/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
    return pd.read_csv(path)

df = load_data()
df.columns = df.columns.str.strip()

st.success(f"Dataset Loaded Successfully: {df.shape[0]} rows")

st.info(" Dataset is pre-uploaded and accessed using a hardcoded local path.")


st.subheader("Dataset Preview")
st.dataframe(df.head(), use_container_width=True)

FEATURES = [
    'Destination Port',
    'Flow Duration',
    'Total Fwd Packets',
    'Packet Length Mean',
    'Active Mean'
]

df = df[FEATURES + ['Label']]

# CLEANING DATASET
df['Label'] = df['Label'].astype(str).str.strip().str.upper()
df = df[df['Label'].isin(['BENIGN', 'DDOS'])]

# NUMERIC CONVERSION
for col in FEATURES:
    df[col] = pd.to_numeric(df[col], errors='coerce')

#  PREPROCESSING 
df.replace([np.inf, -np.inf], np.nan, inplace=True)

numeric_cols = df.select_dtypes(include=[np.number]).columns
df[numeric_cols] = df[numeric_cols].fillna(df[numeric_cols].mean())

#  LABEL ENCODING (To convert categorical text data into numerical intergers)
label_map = {'BENIGN': 0, 'DDOS': 1}
df['Label'] = df['Label'].map(label_map)

#  SPLIT DATA 
X = df[FEATURES]
y = df['Label']

X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=(100 - split_size) / 100,
    random_state=42
)

#  TRAIN MODEL
st.markdown("---")
if st.button("Train Model"):
    model = RandomForestClassifier(
        n_estimators=n_estimators,
        random_state=42
    )
    model.fit(X_train, y_train)
    st.session_state['model'] = model
    st.success("Model trained successfully!")

#  EVALUATION 
if 'model' in st.session_state:
    model = st.session_state['model']
    y_pred = model.predict(X_test)

    st.metric("Accuracy", f"{accuracy_score(y_test, y_pred)*100:.2f}%")
    st.text(classification_report(y_test, y_pred, target_names=['BENIGN', 'DDoS']))

    cm = confusion_matrix(y_test, y_pred)

    # HEAT MAP
    fig, ax = plt.subplots(figsize=(2, 2))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Reds', ax=ax)
    ax.set_xlabel("Predicted Label")
    ax.set_ylabel("Actual Label")
    st.pyplot(fig)

#  LIVE PREDICTION 
st.markdown("---")
st.subheader("Live Network Traffic Analysis")

vals = [
    st.number_input("Destination Port", 1, 65535, 80),
    st.number_input("Flow Duration", 0, 100000, 500),
    st.number_input("Total Fwd Packets", 0, 500, 100),
    st.number_input("Packet Length Mean", 0, 1500, 500),
    st.number_input("Active Mean", 0, 1000, 50)
]

if st.button("Check Traffic"):
    if 'model' in st.session_state:
        pred = model.predict(np.array([vals]))[0]
        st.success(" BENIGN(Normal Network Traffic Detected)" if pred == 0 else " DDoS ATTACK(Malicious Network Activity Detected)")
    else:
        st.warning("Train the model first!")
