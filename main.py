import re
import csv

pattern = re.compile(
    r'(?P<datetime>\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+)\s+\[\*\*\]\s+\[(?P<sid>\d+:\d+:\d+)\]\s+(?P<message>[^\[]+)\s+\[\*\*\]\s+\[Classification:\s*(?P<classification>[^\]]+)\]\s+\[Priority:\s*(?P<priority>\d+)\]\s+\{(?P<protocol>[^\}]+)\}\s+(?P<src_ip>\d+\.\d+\.\d+\.\d+):(?P<src_port>\d+)\s+->\s+(?P<dst_ip>\d+\.\d+\.\d+\.\d+):(?P<dst_port>\d+)'
)

with open('fast.log', 'r') as log_file, open('suricata.csv', 'w', newline='') as csv_file:
    fieldnames = ['Datetime', 'SID', 'Message', 'Classification', 'Priority', 'Protocol', 'Src_IP', 'Src_Port', 'Dst_IP', 'Dst_Port']
    writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
    writer.writeheader()

    for line in log_file:
        match = pattern.match(line)
        if match:
            writer.writerow({
                'Datetime': match.group('datetime'),
                'SID': match.group('sid'),
                'Message': match.group('message').strip(),
                'Classification': match.group('classification').strip(),
                'Priority': match.group('priority'),
                'Protocol': match.group('protocol'),
                'Src_IP': match.group('src_ip'),
                'Src_Port': match.group('src_port'),
                'Dst_IP': match.group('dst_ip'),
                'Dst_Port': match.group('dst_port'),
            })
