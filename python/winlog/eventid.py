import os
import re
import pandas as pd

# 定义事件文件所在目录
directory = './input/'
# Save the DataFrame to a CSV file
csv_file_path = './parsed_events.csv'

# Function to parse the content of a single event
def parse_event_content(content):
    # Create a dictionary for the parsed data
    parsed_data = {
        'value': None,
        'version': None,
        'opcode': None,
        'channel': None,
        'level': None,
        'task': None,
        'keywords': None,
        'message': None
    }

    # Parse the data
    parsed_data['value'] = re.search(r'value: (.*)', content).group(1)
    parsed_data['version'] = re.search(r'version: (.*)', content).group(1)
    parsed_data['opcode'] = re.search(r'opcode: (.*)', content).group(1)
    parsed_data['channel'] = re.search(r'channel: (.*)', content).group(1)
    parsed_data['level'] = re.search(r'level: (.*)', content).group(1)
    parsed_data['task'] = re.search(r'task: (.*)', content).group(1)
    parsed_data['keywords'] = re.search(r'keywords: (.*)', content).group(1)

    # Extracting message which is between 'message:' and the next occurrence of 'event:' or end of string
    message_match = re.search(r'message:(.*?)(?=event:|$)', content, re.DOTALL)
    if message_match:
        parsed_data['message'] = message_match.group(1).strip()

    return parsed_data


# Function to parse a file and extract the events
def parse_event_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        content = file.read()

    # Extract windows version from the file name
    windows_version = re.search(r'Win\d+', file_path).group(0)

    # Split the content into events
    events = re.split(r'event:', content)

    # Parse each event and store the results
    events_data = []
    for event_content in events[1:]:  # Skip the first split as it is before the first 'event:'
        event_data = parse_event_content(event_content)
        event_data['windows_version'] = windows_version
        events_data.append(event_data)

    return events_data


# Initialize a list to hold all parsed events from all files
all_events_data = []

# Iterate over the files in the directory
for filename in os.listdir(directory):
    if filename.endswith(".txt"):
        # Parse the file and extend the list with its events
        file_events = parse_event_file(os.path.join(directory, filename))
        all_events_data.extend(file_events)

# Convert the list of dictionaries to a DataFrame
df_events = pd.DataFrame(all_events_data)

# If there are events with the same ID, we group them and concatenate the windows_version values
df_events_grouped = df_events.groupby(
    ['value', 'version', 'opcode', 'channel', 'level', 'task', 'keywords', 'message'],
    as_index=False)['windows_version'].apply(','.join)

df_events_grouped.to_csv(csv_file_path, index=False)

csv_file_path
