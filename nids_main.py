
# AI Based Network Intrusion Detection System (NIDS)
#For Simulation Mode (Real - world data)

import streamlit as ui
import pandas as pd
import numpy as np

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix

import matplotlib.pyplot as plt
import seaborn as sns


# Streamlit Page Settings

ui.set_page_config(
    page_title="AI NIDS Dashboard",
    layout="wide"
)


# Title and Basic Info

ui.title("AI-Based Network Intrusion Detection System")
ui.write("For Simulation Mode ")
ui.write("""
### Project Overview
This project uses **Machine Learning (Random Forest Algorithm)** to detect  
**malicious network activity**.

The system classifies network traffic into:
- **Benign (Normal Traffic)**
- **Malicious (Attack Traffic)**

This implementation uses **simulated network data** for academic demonstration.
""")


# Generate Sample Network Traffic Data

@ui.cache_data
def create_network_data():
    """
    This function creates sample network traffic data.
    No external CSV file is required.
    """

    np.random.seed(10)
    total_rows = 5000

    traffic_data = {
        "dest_port": np.random.randint(1, 65535, total_rows),
        "flow_time": np.random.randint(100, 100000, total_rows),
        "packet_count": np.random.randint(1, 100, total_rows),
        "avg_packet_size": np.random.uniform(10, 1500, total_rows),
        "active_time": np.random.uniform(0, 1000, total_rows),
        "traffic_label": np.random.choice([0, 1], total_rows, p=[0.7, 0.3])
        # 0 = Benign, 1 = Malicious
    }

    df = pd.DataFrame(traffic_data)

    # Simulate attack patterns
    df.loc[df["traffic_label"] == 1, "packet_count"] += np.random.randint(
        50, 200, df[df["traffic_label"] == 1].shape[0]
    )

    df.loc[df["traffic_label"] == 1, "flow_time"] = np.random.randint(
        1, 1000, df[df["traffic_label"] == 1].shape[0]
    )

    return df

network_df = create_network_data()


# Sidebar Inputs
training_ratio = ui.sidebar.slider(
    "Training Data Percentage",
    min_value=50,
    max_value=90,
    value=80
)
tree_count = ui.sidebar.slider(
    "Number of Trees",
    min_value=10,
    max_value=200,
    value=100
)
# Prepare Data for Model
features = network_df.drop("traffic_label", axis=1)
labels = network_df["traffic_label"]

X_train, X_test, y_train, y_test = train_test_split(
    features,
    labels,
    test_size=(100 - training_ratio) / 100,
    random_state=42
)
# Model Training Section
ui.divider()
left, right = ui.columns([1, 2])

with left:
    ui.subheader("Model Training")

    if ui.button("Train AI Model"):
        with ui.spinner("Training in progress..."):
            rf_model = RandomForestClassifier(
                n_estimators=tree_count,
                random_state=42
            )
            rf_model.fit(X_train, y_train)
            ui.session_state["trained_model"] = rf_model
            ui.success("Model trained successfully!")

    if "trained_model" in ui.session_state:
        ui.info("Model is ready for prediction")
# Model Performance
with right:
    ui.subheader("Model Performance")

    if "trained_model" in ui.session_state:
        model = ui.session_state["trained_model"]
        predictions = model.predict(X_test)

        accuracy = accuracy_score(y_test, predictions)

        a, b, c = ui.columns(3)
        a.metric("Accuracy", f"{accuracy * 100:.2f}%")
        b.metric("Total Records", len(network_df))
        c.metric("Detected Attacks", int(np.sum(predictions)))

        ui.write("Confusion Matrix")

        matrix = confusion_matrix(y_test, predictions)

        fig, ax = plt.subplots(figsize=(4, 3))
        sns.heatmap(matrix, annot=True, fmt="d", cmap="Oranges", ax=ax)
        ui.pyplot(fig)
    else:
        ui.warning("Please train the model first")

# Manual Traffic Testing Section
ui.divider()
ui.subheader("Live Network Traffic Analysis")

ui.write("Enter traffic details to check if it is safe or malicious.")

c1, c2, c3, c4 = ui.columns(4)

input_flow_time = c1.number_input("Flow Duration", 0, 100000, 5000)
input_packets = c2.number_input("Total Packets", 0, 500, 20)
input_packet_size = c3.number_input("Average Packet Size", 0, 1500, 400)
input_active_time = c4.number_input("Active Time", 0, 1000, 200)

if ui.button("Check Traffic"):
    if "trained_model" in ui.session_state:
        model = ui.session_state["trained_model"]

        test_input = np.array([[
            80,  
            input_flow_time,
            input_packets,
            input_packet_size,
            input_active_time
        ]])

        result = model.predict(test_input)

        if result[0] == 1:
            ui.error(" Malicious Network Activity Detected")
            ui.write("Unusual traffic behavior observed.")
        else:
            ui.success(" Normal Network Traffic Detected")
    else:
        ui.error("Train the model before testing traffic")
