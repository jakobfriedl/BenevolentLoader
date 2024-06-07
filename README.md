# BenevolentLoader

Shellcode loader built as part of a capstone exercise for the Maldev Academy syllabus. This loader uses beginner and intermediary malware development concepts like direct syscalls via Hell's Gate, payload staging, payload encryption and several anti-analysis features. 

> [!CAUTION]
> The tools in this repository can inflict harm on systems when executed without caution. I do not condone the use of these programs for any malicious activities.

## Features: 
- [Payload builder](./Builder/)
  - AES encrypted payload
  - XOR protected encryption key
- Remote mapping injection via direct syscalls (Hell's Gate)
- Payload staging via remote webserver
- Brute-force key decryption during runtime
- API hashing
- Delayed execution via API Hammering
- Self-deletion if debugger is detected
- IAT Camouflage

## Screenshots
![image](BenevolentLoader.png)
