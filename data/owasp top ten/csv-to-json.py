import csv
import json

# CSVファイルの読み込み
csv_file_path = "1344.csv"
filtered_rows = []

# CSVファイルを読み込み、フィルタリング
with open(csv_file_path, mode="r", encoding="utf-8") as file:
    reader = csv.DictReader(file)
    for row in reader:
        if row["Weakness Abstraction"] == "Base":
            filtered_rows.append(
                {
                    "CWE-ID": row["CWE-ID"],
                    "Name": row["Name"],
                    "Alternate Terms": row["Alternate Terms"],
                }
            )

# 結果を新しいJSONファイルに保存
filtered_json: dict[str, list] = {"cwe": []}

for row in filtered_rows:
    aliases = [row["Name"]]
    for r in row["Alternate Terms"].strip("::").split("::"):
        if r.startswith("TERM:"):
            term_lst = r.removeprefix("TERM:").split(":DESCRIPTION:")[0].split(" / ")
            aliases.extend(term_lst)
    filtered_json["cwe"].append(
        {
            "cwe-id": "CWE-" + row["CWE-ID"],
            "aliases": list(map(lambda x: x.lower(), aliases)),
        }
    )

output_json_file_path = "cwe-id-dict-v2.json"
with open(output_json_file_path, mode="w", encoding="utf-8") as file:
    json.dump(filtered_json, file, indent=2)
