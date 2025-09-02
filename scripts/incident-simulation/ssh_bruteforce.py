import subprocess
import time
import random

# --- Configuration ---
TARGET_HOST = "192.168.1.14"  # Target the local machine to generate local logs
ATTEMPTS = 15              # Number of failed login attempts to generate

def run_ssh_attempt(username, hostname):
    """
    Attempts a single SSH login using a non-existent password.
    This is designed to fail and generate a log entry.
    The 'sshpass' utility is used to provide a password non-interactively.
    """
    # Using a fake password with sshpass to automate the failure.
    # The command will exit with an error, which is expected.
    command = [
        "sshpass", "-p", f"fakepassword{random.randint(1000,9999)}",
        "ssh",
        "-o", "StrictHostKeyChecking=no",  # Prevents prompts about new host keys
        "-o", "PasswordAuthentication=yes", # Ensure it tries password auth
        "-o", "ConnectTimeout=5",         # Don't wait too long to fail
        f"{username}@{hostname}"
    ]
    
    print(f"Attempting login for user '{username}'...")
    
    # We expect this command to fail, so we capture output and ignore errors.
    subprocess.run(command, capture_output=True, text=True)

def main():
    """Main function to simulate the brute-force attack."""
    print("--- Starting Local SSH Brute-Force Simulation ---")
    print(f"This will generate {ATTEMPTS} failed login events in /var/log/auth.log.")
    print("The Wazuh agent will detect these events and trigger an alert.")
    
    # A list of usernames that don't exist to maximize failure rate
    fake_usernames = ["admin", "test", "guest", "user", "backup", "ftpuser", "webmaster"]
    
    for i in range(ATTEMPTS):
        # Choose a random fake username for each attempt
        user_to_try = random.choice(fake_usernames)
        
        run_ssh_attempt(user_to_try, TARGET_HOST)
        
        # A short, random delay between attempts to mimic a real attacker
        time.sleep(random.uniform(0.5, 2))

    print("\n--- Simulation Complete ---")
    print("Check your Wazuh dashboard for alerts related to 'SSH brute-force' or 'Multiple authentication failures'.")

if __name__ == "__main__":
    # Check if sshpass is installed, as it's required for this script.
    if subprocess.run(["which", "sshpass"], capture_output=True).returncode != 0:
        print("Error: 'sshpass' is not installed. Please install it to run this script.")
        print("On Debian/Ubuntu: sudo apt-get install sshpass")
        print("On CentOS/RHEL: sudo yum install sshpass")
    else:
        main()
