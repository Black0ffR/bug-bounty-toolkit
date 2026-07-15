#!/bin/zsh

LOG_FILE="interactions.log"

# --- LOG ROTATION ---
if [[ -f "$LOG_FILE" ]]; then
    SIZE=$(du -k "$LOG_FILE" | cut -f1)
    if [[ $SIZE -gt 5120 ]]; then
        mv "$LOG_FILE" "${LOG_FILE}.old"
        touch "$LOG_FILE"
    fi
fi

# --- IP INITIALIZATION ---
echo -e "\033[1;34m[*] Fetching your public IP...\033[0m"
MY_IP=$(curl -s https://ifconfig.me)
echo "[*] Your IP: $MY_IP"
echo -e "\033[1;34m[*] Starting Monitor (Voice: 'Target Hit' only)...\033[0m"

# --- MAIN MONITOR ---
stdbuf -oL interactsh-client -server oast.fun -o "$LOG_FILE" 2>&1 | while read -r line; do
    # Display raw output so you can still see data details
    echo "$line"
    
    # Trigger only on actual interactions, ignoring INF noise
    if [[ "$line" == *"["*"]"* ]] && [[ "$line" != *"[INF]"* ]]; then
        
        # Extract Source IP
        IP=$(echo "$line" | grep -oP '\d{1,3}(\.\d{1,3}){3}' | head -n 1)
        
        # Logic: If an IP exists and it is NOT yours, speak "Target Hit"
        if [[ -n "$IP" ]] && [[ "$IP" != "$MY_IP" ]]; then
            
            # Simple, fast voice alert
            espeak -p 50 -s 160 "Target Hit" &
            
            # Visual Notification (Terminal Flash)
            echo -e "\033[?5h"; (sleep 0.1; echo -e "\033[?5l") &
            
            TIMESTAMP=$(date +"%H:%M:%S")
            echo -e "\033[1;31m[!] ALERT: Target ($IP) interacted at $TIMESTAMP\033[0m"
        fi
    fi
done
