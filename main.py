import sys
import pandas as pd
from numpy import random
from glob import glob
from os import path
from sklearn.preprocessing import MinMaxScaler
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report

# TODO: Refactor to accept a training and validating directory to prevent overfitting
# TODO: Refactor to make OOP
# TODO: More robust model evaluation

def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py <directory_path>")
        sys.exit(1)

    directory_path = sys.argv[1]

    data_loader = DataLoader()
    data = data_loader.load_data(directory_path)\

    print(data.head())


class DataLoader:

    def load_data(self, directory_path: str) -> pd.DataFrame:
        csv_files = glob(path.join(directory_path, '*.csv'))

        if not csv_files:
            print(f"No CSV files found in the specified directory: {directory_path}")
            sys.exit(1)

        dataSets = []

        for file in csv_files:
                dataSets.append(pd.read_csv(file))

        return self.__preprocess_data__(pd.concat(dataSets, ignore_index=True))
    

    def __preprocess_data__(self, data: pd.DataFrame) -> pd.DataFrame:
        data['Source IP'] = self.__synthesize_ip__(len(data))
        data['Destination IP'] = self.__synthesize_ip__(len(data))
        data['Label'] = data['Label'].apply(lambda x: 0 if x == 'BENIGN' else 1)

        data = data[['Source IP', 'Destination IP', 'Flow Duration', 'Total Fwd Packets', 
               'Total Backward Packets', 'Label']]

        data.dropna()

        scaler = MinMaxScaler()
        data[['Flow Duration', 'Total Fwd Packets', 'Total Backward Packets']] = scaler.fit_transform(
            data[['Flow Duration', 'Total Fwd Packets', 'Total Backward Packets']])
        return data


    def __synthesize_ip__(self, num : int) -> list:
        return [f"192.168.{random.randint(0, 256)}.{random.randint(0, 256)}" for _ in range(num)]


class ModelTrainer:
    def train_model(data: pd.DataFrame):
        X = data[['Flow Duration', 'Total Fwd Packets', 'Total Backward Packets']]
        y = data['Label']
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

        # Train the model
        model = LogisticRegression()
        model.fit(X_train, y_train)

        return model, X_test, y_test


    def detect_malicious_iPs(model, data: pd.DataFrame):
        data['Prediction'] = model.predict(data)

        # Extract malicious IPs
        malicious_ips = data[data['Prediction'] == 1]['Source IP'].unique()
        print("Malicious IPs Detected:", malicious_ips)


    def store_malicious_iPs(malicious_ips: list):
        malicious_ips = list(malicious_ips)

        # Save to a file
        with open("malicious_ips.txt", "w") as file:
            for ip in malicious_ips:
                file.write(ip + "\n")


    



if __name__ == '__main__':
    main()
