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
    average_gain = gain.ewm(com=window-1, min_periods=window).mean()
    average_loss = loss.ewm(com=window-1, min_periods=window).mean()
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
            continuous_data = data.iloc[start_idx:i]
            continuous_data = calculate_moving_averages(continuous_data)
            continuous_data['RSI_14'] = calculate_rsi(continuous_data)
            continuous_data = calculate_macd(continuous_data)

            # Append the processed segment to the full processed data
            processed_data = processed_data.append(continuous_data, ignore_index=True)

            # Update the start index for the next segment
            start_idx = i

    # Process the final segment
    final_segment = data.iloc[start_idx:]
    final_segment = calculate_moving_averages(final_segment)
    final_segment['RSI_14'] = calculate_rsi(final_segment)
    final_segment = calculate_macd(final_segment)

    # Append the final processed segment
    processed_data = processed_data.append(final_segment, ignore_index=True)

    return processed_data

# Main function to process all CSV files in the given directory
def process_all_csv_in_directory(directory_path):
    # Iterate over all files in the directory
    for file_name in os.listdir(directory_path):
        # Check if the file is a CSV file
        if file_name.endswith('.csv'):
            file_path = os.path.join(directory_path, file_name)

            # Process each file
            try:
                print(f"Processing file: {file_name}")
                data = process_file_with_time_gaps(file_path)

                # Save the processed data to a new CSV file
                save_path = os.path.join(directory_path, f"processed_{file_name}")
                data.to_csv(save_path, index=False)
                print(f"Processed data saved to: {save_path}")
            except Exception as e:
                print(f"Failed to process file: {file_name}. Error: {e}")

# Example usage:
directory_path = '/training/Data/binanceData/high_frequency'  # Replace with your actual directory path
process_all_csv_in_directory(directory_path)