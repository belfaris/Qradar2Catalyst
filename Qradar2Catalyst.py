import subprocess
import json
import time
import logging
import os
from datetime import datetime

# Configuration
QRADAR_URL = os.getenv("QRADAR_URL", "<YOUR_Qradar_URL>")
QRADAR_API_TOKEN = os.getenv("QRADAR_API_TOKEN", "QRADAR_API_TOKEN")
CATALYST_URL = os.getenv("CATALYST_URL", "<YOUR_CATALYST_URL")
CATALYST_TOKEN = os.getenv("CATALYST_TOKEN", "<_YOUR_CATALYST_API_TOKEN")
SYNC_INTERVAL = int(os.getenv("SYNC_INTERVAL", 60))  # in minutes
QRADAR_RESULT_FILE = "qradar_offenses.json"  # File to store QRadar offenses

# Setup logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def fetch_qradar_offenses():
    curl_command = [
        "curl", "-k", "-S", "-X", "GET",
        "-H", f"SEC: {QRADAR_API_TOKEN}",
        "-H", "Range: items=0-49",
        "-H", "Version: 21.0",
        "-H", "Accept: application/json",
        f"{QRADAR_URL}/api/siem/offenses"
    ]
    logging.debug(f"Executing command: {' '.join(curl_command)}")
    try:
        result = subprocess.run(curl_command, capture_output=True, text=True, check=True)
        logging.debug(f"Curl output: {result.stdout}")
        offenses = json.loads(result.stdout)
        with open(QRADAR_RESULT_FILE, "w") as file:
            json.dump(offenses, file)  # Write offenses to file
        return offenses
    except subprocess.CalledProcessError as e:
        logging.error(f"Error fetching QRadar offenses: {e.stderr}")
        return []
    except json.JSONDecodeError as e:
        logging.error(f"Error parsing JSON response: {e}")
        return []

def send_to_catalyst():
    with open(QRADAR_RESULT_FILE, "r") as file:
        offenses = json.load(file)

    for offense in offenses:
        # Convert the start_time from timestamp to ISO 8601 string format
        start_time = offense.get("start_time")
        created_time = datetime.utcfromtimestamp(start_time / 1000).isoformat() + 'Z' if start_time else None

        payload = {
            "id": offense.get("id", "No ID"),
            "name": offense.get("description", "No Description"),
            "owner": "qradar",
            "read": ["bob"],
            "references": [{"href": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=cve-2017-0144",
                            "name": "CVE-2017-0144"}],
            "created": created_time,
            "schema": "{}",
            "status": "open",
            "type": "alert",
            "write": ["alice"]
        }

        payload_json = json.dumps(payload)

        curl_command = [
            "curl", "-k", "-S", "-X", "POST", f"{CATALYST_URL}/api/tickets",
            "-H", "accept: application/json",
            "-H", "Content-Type: application/json",
            f"-H", f"PRIVATE-TOKEN: {CATALYST_TOKEN}",
            "-d", payload_json
        ]

        # Print the full curl command for debugging purposes
        curl_command_str = ' '.join(curl_command)
        logging.debug(f"Executing command: {curl_command_str}")
        logging.debug(f"Payload: {payload_json}")

        try:
            result = subprocess.run(curl_command, capture_output=True, text=True, check=True)
            logging.debug(f"Curl output: {result.stdout}")
            logging.debug(f"Curl error (if any): {result.stderr}")
            if result.returncode == 0:
                logging.info(f"Successfully sent offense {offense.get('id')} to Catalyst")
            else:
                logging.error(f"Error sending offense to Catalyst: {result.stderr}")
        except subprocess.CalledProcessError as e:
            logging.error(f"Error sending offense to Catalyst: {e.stderr}")

def sync_data():
    while True:
        try:
            fetch_qradar_offenses()
            send_to_catalyst()
        except Exception as e:
            logging.error(f"Unexpected error during sync: {e}")
        time.sleep(SYNC_INTERVAL * 60)

if __name__ == "__main__":
    sync_data()
