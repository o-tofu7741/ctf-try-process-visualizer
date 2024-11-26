import json
from datetime import datetime
from pprint import pprint

import chardet


def parse_audit_logs() -> list[dict]:
    # Path to the JSON file
    json_cwe_filepath = "data/cwe-id-dict.json"
    json_log_filepath = "log/servers/audit-log-3.json"

    # List of messages to ignore
    ignore_ruleId = ["930110", "949110", "920350", "200004"]

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
                    lambda x: x["details"]["ruleId"] not in ignore_ruleId,
                    transaction_details["messages"],
                )
            )
            if len(messages) == 0:
                raise Exception("No messages found")

        except Exception as e:
            print(f"Error processing transaction: {e}")
            continue
        else:
            cwe_id: str = find_cwe_id(messages, cwe_dict)
            parsed_data.append(
                {
                    "client_ip": client_ip,
                    "time_stamp": time_stamp,
                    "unique_id": unique_id,
                    "request": req,
                    "response": res,
                    "messages": messages,
                    "cwe_id": cwe_id,
                }
            )
    with open("parsed_data.json", "w") as f:
        json.dump(parsed_data, f, indent=2)
    return parsed_data


def find_cwe_id(messages, cwe_dict) -> str:
    cwe_id_list: dict[str, int] = {"Unknown": 0}
    for cwe in cwe_dict["cwe"]:
        cwe_id = cwe["cwe-id"]
        aliases = cwe["aliases"]
        for alias in aliases:
            for message in messages:
                if alias in message["message"]:
                    cwe_id_list[cwe_id] = cwe_id_list.get(cwe_id, 0) + 1
                for audit_value in message["details"].values():
                    if isinstance(audit_value, list):
                        for v in audit_value:
                            if alias in v:
                                cwe_id_list[cwe_id] = cwe_id_list.get(cwe_id, 0) + 1
                    else:
                        if alias in audit_value:
                            cwe_id_list[cwe_id] = cwe_id_list.get(cwe_id, 0) + 1
    # print(f"\n{cwe_id_list=}")
    # for message in messages:
    #     print(f"""{message["details"]["ruleId"]=}message["message"]""")
    return max(cwe_id_list, key=lambda k: int(cwe_id_list[k]))


def ip_cwe_map(data: list[dict]) -> dict:
    client_ip_cwe_map: dict = {}
    for transaction in data:
        client_ip = transaction["client_ip"]
        cwe_id = transaction["cwe_id"]
        time_stamp = transaction["time_stamp"]
        if client_ip not in client_ip_cwe_map:
            client_ip_cwe_map[client_ip] = []
        client_ip_cwe_map[client_ip].append((time_stamp, cwe_id))
    return client_ip_cwe_map


def parse_date(date_str):
    date_format = "%a %b %d %H:%M:%S %Y"
    return datetime.strptime(date_str, date_format)


def detect_encoding(file_path: str) -> str:
    with open(file_path, "rb") as f:
        enc = chardet.detect(f.read())["encoding"] or "utf-8"
    return enc


if __name__ == "__main__":
    parsed_data = parse_audit_logs()

    def plot_cwe_transitions(client_ip_cwe_map):
        import plotly.graph_objects as go

        for client_ip, cwe_list in client_ip_cwe_map.items():
            cwe_list.sort(key=lambda x: x[0])  # 時間順にソート
            times, cwe_ids = zip(*cwe_list)

            fig = go.Figure()
            fig.add_trace(
                go.Scatter(x=times, y=cwe_ids, mode="lines+markers", name=client_ip)
            )
            fig.update_layout(
                title=f"CWE ID Transitions for Client IP: {client_ip}",
                xaxis_title="Time",
                yaxis_title="CWE ID",
                xaxis=dict(tickformat="%Y-%m-%d %H:%M:%S", tickangle=45),
                autosize=False,
                width=1000,
                height=500,
            )
            fig.show()

    # plot_cwe_transitions(client_ip_cwe_map)
