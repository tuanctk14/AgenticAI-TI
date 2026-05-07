from tools.opencti_client import fetch_opencti_indicators

result = fetch_opencti_indicators('emotet', 'all')
print(f'Result source: {result["source"]}')
print(f'Count: {len(result["context"])}')
for i in result['context']:
    print(f'  - {i["name"]}: {i["threat_actor"]}')
