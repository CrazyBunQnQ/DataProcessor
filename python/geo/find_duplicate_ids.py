import json
import argparse
from collections import Counter
import sys

def find_duplicates(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
        if not isinstance(data, list):
            print("Error: The JSON file does not contain a list/array.")
            return

        ids = []
        for index, item in enumerate(data):
            if isinstance(item, dict) and 'id' in item:
                ids.append(item['id'])
            else:
                # print(f"Warning: Item at index {index} is not a dictionary or does not have an 'id' field.")
                pass
        
        id_counts = Counter(ids)
        duplicates = [id_val for id_val, count in id_counts.items() if count > 1]
        
        if duplicates:
            print("Duplicate IDs found:")
            for dup_id in duplicates:
                print(dup_id)
            print(f"Total duplicate IDs: {len(duplicates)}")
        else:
            print("No duplicate IDs found.")

    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
    except json.JSONDecodeError:
        print(f"Error: Failed to decode JSON from '{file_path}'.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Find duplicate IDs in a JSON array file.")
    parser.add_argument("file", help="Path to the JSON file")
    
    args = parser.parse_args()
    find_duplicates(args.file)
