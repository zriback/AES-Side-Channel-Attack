import json
import numpy as np

DATA_FILEPATH = 'data/t00.json'


def load_data(data_filepath: str) -> dict:
    with open(data_filepath, 'r') as f:
        data = json.load(f)
    return data


def extract_data(data: dict):
    pass

def calculate_statistics(data: dict):
    pass


def main():
    data = load_data(DATA_FILEPATH)
    traces = data['traces']

    print(f'Loaded {len(traces)} traces from the data file.')



if __name__ == '__main__':
    main()