import os
import pandas as pd


# Function to load the data
def load_data(file_path):
    return pd.read_csv(file_path)


# Function to calculate SMAs and EMAs
def calculate_moving_averages(data, short_window=5, long_window=10):
    data['SMA_5'] = data['Close'].rolling(window=short_window).mean()
    data['SMA_10'] = data['Close'].rolling(window=long_window).mean()
    data['EMA_5'] = data['Close'].ewm(span=short_window, adjust=False).mean()
    data['EMA_10'] = data['Close'].ewm(span=long_window, adjust=False).mean()
    return data


# Function to calculate RSI
def calculate_rsi(data, window=14):
    delta = data['Close'].diff()
    gain = (delta.where(delta > 0, 0)).fillna(0)
    loss = (-delta.where(delta < 0, 0)).fillna(0)
    average_gain = gain.ewm(com=window - 1, min_periods=window).mean()
    average_loss = loss.ewm(com=window - 1, min_periods=window).mean()
    rs = average_gain / average_loss
    rsi = 100 - (100 / (1 + rs))
    return rsi


# Function to calculate MACD and Signal Line
def calculate_macd(data):
    data['MACD'] = data['Close'].ewm(span=12, adjust=False).mean() - data['Close'].ewm(span=26, adjust=False).mean()
    data['Signal_Line'] = data['MACD'].ewm(span=9, adjust=False).mean()
    return data


# Main function to process the data
def process_data(file_path):
    # Load data
    data = load_data(file_path)

    # Calculate moving averages
    data = calculate_moving_averages(data)

    # Calculate RSI
    data['RSI_14'] = calculate_rsi(data)

    # Calculate MACD and Signal Line
    data = calculate_macd(data)

    return data


def add_future_high_low(data, future_periods=10):
    # Calculate future high and low relative to the current open price
    # Avoid division by zero by replacing 0 with NaN and then backfilling with the next valid open price
    open_prices = data['Open'].replace(0, pd.NA).bfill()

    # Calculate the future high and low within the next 10 minutes
    future_highs = data['High'].rolling(window=future_periods, min_periods=1).max().shift(-future_periods)
    future_lows = data['Low'].rolling(window=future_periods, min_periods=1).min().shift(-future_periods)

    # Calculate the expected high and low increases as a percentage
    data['Expected_High_Increase'] = (future_highs - open_prices) / open_prices
    data['Expected_Low_Increase'] = (future_lows - open_prices) / open_prices

    # Fill any remaining NaN values that may have been caused by the shift operation (at the end of the DataFrame)
    data['Expected_High_Increase'].fillna(method='ffill', inplace=True)
    data['Expected_Low_Increase'].fillna(method='ffill', inplace=True)

    return data


# Function to process a single file with consideration for time gaps
def process_file_with_time_gaps(file_path):
    # Load data
    data = load_data(file_path)

    # Convert 'Time' column to datetime
    data['Time'] = pd.to_datetime(data['Time'])

    # Sort the data by time just in case it's not in order
    data.sort_values('Time', inplace=True)

    # Initialize an empty DataFrame to store processed data
    processed_data = pd.DataFrame()

    # Process each segment of continuous data
    start_idx = 0
    for i in range(1, len(data)):
        # Check for a time gap greater than 1 minute
        if (data['Time'].iloc[i] - data['Time'].iloc[i - 1]) > pd.Timedelta(minutes=1):
            # Process the continuous segment
            # Make an explicit copy of the segment to avoid SettingWithCopyWarning
            continuous_data = data.iloc[start_idx:i].copy()
            continuous_data = calculate_moving_averages(continuous_data)
            continuous_data['RSI_14'] = calculate_rsi(continuous_data)
            continuous_data = calculate_macd(continuous_data)
            continuous_data = add_future_high_low(continuous_data)

            # Append the processed segment to the full processed data
            processed_data = pd.concat([processed_data, continuous_data], ignore_index=True)

            # Update the start index for the next segment
            start_idx = i

    # Process the final segment
    # Make an explicit copy of the segment to avoid SettingWithCopyWarning
    final_segment = data.iloc[start_idx:].copy()
    final_segment = calculate_moving_averages(final_segment)
    final_segment['RSI_14'] = calculate_rsi(final_segment)
    final_segment = calculate_macd(final_segment)
    final_segment = add_future_high_low(final_segment)

    # Append the final processed segment
    processed_data = pd.concat([processed_data, final_segment], ignore_index=True)

    return processed_data


# Main function to process all CSV files in the given directory
def process_all_csv_in_directory(input_path, output_path):
    # Iterate over all files in the directory
    for file_name in os.listdir(input_path):
        # Check if the file is a CSV file
        if file_name.endswith('.csv'):
            file_path = os.path.join(input_path, file_name)

            # Process each file
            try:
                print(f"Processing file: {file_name}")
                data = process_file_with_time_gaps(file_path)

                # Save the processed data to a new CSV file
                save_path = os.path.join(output_path, f"processed_{file_name}")
                data.to_csv(save_path, index=False)
                print(f"Processed data saved to: {save_path}")
            except Exception as e:
                print(f"Failed to process file: {file_name}. Error: {e}")


# Example usage:
input_path = '/training/Data/binanceData/high_frequency/collected'  # Replace with your actual directory path
output_path = '/training/Data/binanceData/high_frequency/processed'  # Replace with your directory path
process_all_csv_in_directory(input_path, output_path)
print("complete")

import pandas as pd
import os
from scipy.stats import zscore
from glob import glob

# Define the input and output directories
input_directory = '/training/Data/binanceData/high_frequency/processed'
output_directory = '/training/Data/binanceData/high_frequency/train'

# Make sure the output directory exists
os.makedirs(output_directory, exist_ok=True)

# List all CSV files in the input directory
csv_files = glob(os.path.join(input_directory, '*.csv'))

# Process each file
for file_path in csv_files:
    try:
        print(f"Processing file: {file_path}")
        # Load the data
        data = pd.read_csv(file_path)

        # Drop rows with any NaN values and create a copy to avoid SettingWithCopyWarning
        data_cleaned = data.dropna().copy()

        # Apply Z-Score normalization to all columns except 'Time' and future price columns
        cols_to_normalize = data_cleaned.columns.difference(['Time', 'Future_High', 'Future_Low'])
        data_cleaned.loc[:, cols_to_normalize] = data_cleaned.loc[:, cols_to_normalize].apply(zscore)

        # Define the output file path
        output_file_path = os.path.join(output_directory, os.path.basename(file_path))

        # Save the cleaned data to the output directory
        data_cleaned.to_csv(output_file_path, index=False)
        print(f"File processed and saved to: {output_file_path}")

    except Exception as e:
        print(f"An error occurred while processing {file_path}: {e}")
