import os
import sys

# Predefined script paths (customize these paths as needed)
SCRIPT_PATHS = {
    "1": "net_discovery/net.py",  # Replace with the actual path to script 1
    "2": "port_scan/porter.py",  # Replace with the actual path to script 2
    "3": "os_detect/n_osdec.py",  # Replace with the actual path to script 3
}

def display_menu():
    """Display the main menu."""
    print("\n--- Script Executor Menu ---")
    print("1. Scan Network")
    print("2. Scan Port")
    print("3. Detect OS")
    print("4. Exit")

def execute_script(script_path):
    """Execute the selected script."""
    if os.path.exists(script_path):
        print(f"Executing script: {script_path}")
        os.system(f"python3 {script_path}")
    else:
        print(f"Error: {script_path} does not exist.")

def main():
    """Main function to display menu and execute scripts."""
    while True:
        display_menu()
        choice = input("Choose an option (1-4): ")

        if choice == "1":
            execute_script(SCRIPT_PATHS["1"])
        elif choice == "2":
            execute_script(SCRIPT_PATHS["2"])
        elif choice == "3":
            execute_script(SCRIPT_PATHS["3"])
        elif choice == "4":
            print("Exiting...")
            break  # Exit the loop and terminate the program
        else:
            print("Invalid option. Please choose a valid option (1-4).")

if __name__ == "__main__":
    main()
