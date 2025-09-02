import os
import time

# --- Configuration ---
# We will create a file in a directory monitored by Wazuh's FIM by default.
# /etc/ is a perfect candidate for this test.
FILE_PATH = "/etc/suspicious_config.txt"

def main():
    """
    Creates and then deletes a file in a critical system directory
    to test Wazuh's File Integrity Monitoring (FIM).
    """
    print("--- Starting File Integrity Monitoring (FIM) Tampering Simulation ---")
    
    # This script needs to be run with root privileges to write to /etc/
    if os.geteuid() != 0:
        print("\nError: This script must be run as root (or with sudo) to write to /etc/.")
        print("Please run it like: sudo python3 fim_tamper_simulator.py")
        return

    try:
        print(f"\n[1] Creating a suspicious file: {FILE_PATH}")
        with open(FILE_PATH, "w") as f:
            f.write("This is a test file created to trigger a Wazuh FIM alert.\n")
            f.write("If you see an alert for this file, the test was successful.\n")
        
        print("File created successfully.")
        print("Wazuh agent should detect this change on its next FIM scan.")
        
        # Wait for a bit to ensure the creation event is processed
        time.sleep(15)

    except Exception as e:
        print(f"An error occurred during file creation: {e}")
        return
    finally:
        # Clean up the file so the system is not left in a modified state.
        if os.path.exists(FILE_PATH):
            print(f"\n[2] Cleaning up by deleting the file: {FILE_PATH}")
            os.remove(FILE_PATH)
            print("File deleted successfully.")
            print("This deletion will also generate a FIM alert.")

    print("\n--- Simulation Complete ---")
    print("Check your Wazuh dashboard for alerts related to 'File added to the system' and 'File deleted'.")

if __name__ == "__main__":
    main()
