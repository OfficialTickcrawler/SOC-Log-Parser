# A simple SOC Log parser& Automation script

# Description: This script is a basic SOC automation tool that scans log files for failed login attempts, unauthorized users, and access to restricted assets. 
# It uses simple string checks to identify potential security incidents and prints alerts accordingly.
# The script also keeps count of failed login attempts and provides a summary at the end of the analysis.

log_file_path = "/Users/dwellz/Documents/server_access.log"

print("[*] Scanning log files sytandby....")
print("_" * 50)

# adds a counter to keep track of the number of failed log attempts
failed_attempts = 0

# adds a list of unauthorized users to flag in the log
dont_allow_list = ["j_doe", "temp_vendor", "guest", "unknown"]

# adds a list of assets that only authorized users are allowed to access
restricted_assets = ["Server-Room-DC", "Finance-PC", "Database-SRV", "HR-Laptop"]

# Open and read the log file line by line
with open(log_file_path, "r") as file:
    for line in file:

        # Clean up the line so all checks can use it safely
        cleaned_line = line.strip()

        # Skip comments and empty lines
        if cleaned_line.startswith("#") or cleaned_line == "":
            continue

        if "STATUS: FAILED" in cleaned_line:
            failed_attempts += 1
            print(f"[alert] FAILED LOGIN ATTEMPT DETECTED! -> {cleaned_line}")
        
        if "STATUS: SUCCESS" in cleaned_line:
            suspicious = False

            # checks for unauthorized users in the line
            if any(user in cleaned_line for user in dont_allow_list):
                print(f"[alert] UNAUTHORIZED USER DETECTED! -> {cleaned_line}")
                suspicious = True

                # checks for access to restricted assets in the line
                if any(assets in cleaned_line for assets in restricted_assets):
                    print(f"[alert] UNAUTHORIZED ASSET ACCESS DETECTED! -> {cleaned_line}")
            if not suspicious:
                print(f"[info] Authorized login -> {cleaned_line}")
                
print("_" * 50)
print(f"[*] Analysis Complete. Total failed attempts: {failed_attempts}")

<img width="1088" height="308" alt="Logs" src="https://github.com/user-attachments/assets/28d57e47-4644-4b19-9f57-9075773e32da" />
