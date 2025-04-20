# Network-based-attack-on-Container
# Summary
This repository contains Python scripts for monitoring system metrics, detecting potential Denial of Service (DoS) attacks and implementing automated mitigation actions. This repository contains python scripts for monitoing, detecting, and mittigating SYN flood attack on a container.
# Requirement
Python3 - to run python programs Docker - for container environment sqlite3 - to create data base and store data scapy - to get access to python lyberaris and to run codes
# Execution
Install all the pre requirements and start by running SYN attack on a targetd IP address. Next in a new terminal run final_monitoring.py scrypt, it will start capturing the data packets, now in a new tab run detect_syn_flood.py code to observe the database and block the traffic from source by blocking the IP address if he is the one who is performing, SYn attack.
# Expected Output
If the SYN attack is active then it reflect with "Blocked incoming traffic from 'IP Address' SYN flood attack detected! SYn count: XX, Blocking IP: 'IP Address'" IP Address - Attacker IP address xx - Numeric integer. If there is no attack No SYN flood attack detected. SYN count: x” (x could be any integer
