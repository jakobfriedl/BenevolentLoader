# BenevolentLoader

Shellcode loader using direct syscalls via Hell's Gate and payload encryption.

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
