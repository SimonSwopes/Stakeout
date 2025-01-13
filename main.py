import pandas as pd

def main():
    # Small Script to see a preview of the labeled data
    filePath = 'Data\Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv'
    data = pd.read_csv(filePath)

    print(data.head())
    print(data.columns)

if __name__ == '__main__':
    main()