import json
from pprint import pprint

# Path to the JSON file
file_path = "log/modsec_audit.json"

# Read and parse the JSON file
data = []
with open(file_path, "r", encoding="utf-8") as file:
    for line in file:
        data.append(json.loads(line))

# Print the parsed data
print(len(data))
pprint(list(map(lambda x: x["transaction"]["request"]["uri"], data)))
pprint(list(map(lambda x: x["transaction"]["request"]["headers"], data)))
pprint(
    list(
        map(
            lambda x: x["transaction"].get("messages", None),
            data,
        )
    )
)
