import json
from datetime import datetime
from pprint import pprint

import chardet


def parse_audit_logs() -> list[dict]:
    # Path to the JSON file
    json_cwe_filepath = "data/cwe-id-dict.json"
    json_log_filepath = "log/servers/server-1-modsec_audit-1122-1223.json"

    # List of messages to ignore
    ignore_cwe_messages = ["Host header is a numeric IP address"]

    with open(
        json_cwe_filepath, "r", encoding=detect_encoding(json_cwe_filepath)
    ) as file:
        cwe_dict = json.load(file)

    # Read and parse the JSON file
    data: list[dict] = []
    with open(
        json_log_filepath, "r", encoding=detect_encoding(json_log_filepath)
    ) as file:
        for line in file:
            data.append(json.loads(line))

    # Parse the data
    parsed_data = []

    for transaction in data:
        try:
            transaction_details: dict = transaction["transaction"]
            client_ip: str = transaction_details["client_ip"]
            time_stamp: str = transaction_details["time_stamp"]

            unique_id: str = transaction_details["unique_id"]

            req: dict = transaction_details["request"]
            res: dict = transaction_details["response"]

            messages: list[dict] = list(
                filter(
                    lambda x: x["message"] not in ignore_cwe_messages,
                    transaction_details["messages"],
                )
            )
            if len(messages) == 0:
                raise Exception("No messages found")

        except Exception as e:
            print(f"Error processing transaction: {e}")
            continue
        else:
            parsed_data.append(
                {
                    "client_ip": client_ip,
                    "time_stamp": parse_date(time_stamp),
                    "unique_id": unique_id,
                    "request": req,
                    "response": res,
                    "messages": list(map(parse_message, messages)),
                    "cwe_id": find_cwe_id(messages[0], cwe_dict),
                }
            )

    return parsed_data


def parse_message(message: dict) -> dict:
    message_str: str = message["message"]
    message_match: str = message["details"]["match"]
    message_file: str = message["details"]["file"]
    message_tags: list[str] = message["details"]["tags"]

    return {
        "message": message_str,
        "match": message_match,
        "file": message_file,
        "tags": message_tags,
    }


def find_cwe_id(message: dict, cwe_dict: dict) -> str:
    cwe_id_list: dict[str, int] = {}

    for cwe in cwe_dict["cwe"]:
        cwe_id = cwe["cwe-id"]
        for keyword in cwe["alias"]:
            for key, value in message.items():
                if key is list:
                    for item in value:
                        if keyword in item:
                            cwe_id_list[cwe_id] = cwe_id_list.get(cwe_id, 0) + 1
                else:
                    if keyword in value:
                        cwe_id_list[cwe_id] = cwe_id_list.get(cwe_id, 0) + 1

    return max(cwe_id_list) if cwe_id_list else "Unknown"


def parse_date(date_str: str) -> datetime:
    date_format = "%a %b %d %H:%M:%S %Y"
    return datetime.strptime(date_str, date_format)


def detect_encoding(file_path: str) -> str:
    with open(file_path, "rb") as f:
        enc = chardet.detect(f.read())["encoding"] or "utf-8"
    return enc


if __name__ == "__main__":
    pprint(parse_audit_logs())
