import sys
import pandas as pd
from numpy import random
from glob import glob
from os import path

def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py <directory_path>")
        sys.exit(1)

    directory_path = sys.argv[1]
    data = load_data(directory_path)
    print(data.head())
    print(len(data))


def load_data(directory_path: str) -> pd.DataFrame:
    csv_files = glob(path.join(directory_path, '*.csv'))

    if not csv_files:
        print("No CSV files found in the specified directory")
        sys.exit(1)

    dataSets = []

    for file in csv_files:
            dataSets.append(pd.read_csv(file))
    
    return format_data(pd.concat(dataSets, ignore_index=True))

def format_data(data: pd.DataFrame) -> pd.DataFrame:
    data['Source IP'] = synthesize_ip(len(data))
    data['Destination IP'] = synthesize_ip(len(data))

    return data[['Source IP', 'Destination IP', 'Flow Duration', 'Total Fwd Packets', 
           'Total Backward Packets', 'Label']]


def synthesize_ip(num : int) -> list:
    return [f"192.168.{random.randint(0, 256)}.{random.randint(0, 256)}" for _ in range(num)]

if __name__ == '__main__':
    main()