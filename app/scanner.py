import json
import os

def read_cloudtrail_logs(log_folder="sample_logs"):
    """
    Read all JSON files in the given folder and return a list of CloudTrail events.
    Each file is expected to be a JSON with a top-level key 'Records'.
    """
    events = []
    if not os.path.isdir(log_folder):
        return events

    for filename in os.listdir(log_folder):
        if filename.endswith(".json"):
            file_path = os.path.join(log_folder, filename)
            with open(file_path, "r") as f:
                try:
                    data = json.load(f)
                    if isinstance(data, dict) and "Records" in data:
                        events.extend(data["Records"])
                except json.JSONDecodeError:
                    print(f"Skipping invalid JSON file: {file_path}")
    return events
