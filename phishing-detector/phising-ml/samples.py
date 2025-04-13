# Install dependencies as needed:
# pip install kagglehub[pandas-datasets]

import kagglehub
from kagglehub import KaggleDatasetAdapter

import pandas as pd

# Set the path to the file you'd like to load
file_path = "PhiUSIIL_Phishing_URL_Dataset.csv"

# Load the latest version of the dataset
df = kagglehub.load_dataset(
    KaggleDatasetAdapter.PANDAS,
    "ndarvind/phiusiil-phishing-url-dataset",
    file_path
)

# Extract the first 5 records
df_head = df.head()

# Export to CSV
df_head.to_csv("sample.csv", index=False)

print("Exported the first 5 records to sample.csv")
