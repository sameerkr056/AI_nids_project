# AI-Based Network Intrusion Detection System (NIDS)
This project implements an AI-powered Network Intrusion Detection System to identify Malicious attacks in network traffic using machine learning. A Random Forest model analyzes network features and classifies traffic as benign or malicious through an interactive dashboard.

The system classifies network traffic into:
- BENIGN (Normal traffic)
- Malicious (Malicious traffic)

---

## 📁 Project Files Description

- **nids_main.py**
  - Simulation Mode
  - Uses generated/simulated network traffic data
  - No external dataset required

- **nids_main1.py**
  - Production Mode
  - Uses real-world network traffic data
  - Designed to work with the **CIC-IDS 2017 dataset**
  - Used for real dataset-based training and testing


## 📊 Dataset Information

This project is based on the **CIC-IDS 2017 dataset**, which is a standard
benchmark dataset for intrusion detection research.

⚠️ **Note:**  
The CIC-IDS 2017 CSV files are **very large in size** and exceed GitHub's
file upload limit. Therefore, the dataset is **not included** in this repository.

### 🔗 Official Dataset Download Link:
http://cicresearch.ca/CICDataset/CIC-IDS-2017/Dataset/CIC-IDS-2017/CSVs/

After downloading the dataset, update the file path in `nids_main1.py`
to run the project in production mode.


## 🛠 Technologies Used
- Python
- Machine Learning
- Random Forest Algorithm
- Scikit-learn
- Pandas & NumPy
- Streamlit
- Matplotlib & Seaborn
- CIC-IDS 2017 Dataset

## How to Run the Project

### Simulation Mode:
```bash
python -m streamlit run nids_main.py
