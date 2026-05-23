# File-Integrity-Monitor-A-python-based-project

1. What Is This Project?
The File Integrity Monitor (FIM) is a cybersecurity tool built in Python that continuously watches over files in a directory and raises an alert whenever something changes secretly. It detects three types of threats that are invisible to a human just browsing folders:

•Files that were secretly modified (even a single byte change is detected)
•Files that were deleted (to cover an attacker's tracks)
•New files that were planted (malware, web shells, or payloads)
•Files disguised with fake extensions (e.g., a virus saved as a .jpg photo)

This type of tool is used professionally by security teams at banks, hospitals, government departments, and any organization where file tampering is a serious risk. It is a core component of many compliance frameworks such as PCI-DSS, HIPAA, and SOC 2.
