import os
import subprocess
import sys

# Determine the current platform
platform = sys.platform

# Check if the current directory is a Git repository
def is_git_repo():
    try:
        result = subprocess.run(['git', 'rev-parse', '--is-inside-work-tree'], 
                                stdout=subprocess.PIPE, 
                                stderr=subprocess.PIPE, 
                                check=True)
        return result.returncode == 0
    except subprocess.CalledProcessError:
        return False

# Get the latest commit message and author for available updates
def get_update_info():
    try:
        log_output = subprocess.check_output(['git', 'log', 'HEAD..origin/main', '--oneline', '--pretty=format:%h %an: %s'], 
                                             stderr=subprocess.PIPE).decode().strip()
        return log_output
    except subprocess.CalledProcessError as e:
        print("Error retrieving update information:", e.stderr.decode())
        return None

# Pull updates from the repository
def update_repo():
    print("Fetching the latest changes from the remote repository...")
    try:
        subprocess.run(['git', 'fetch', 'origin'], check=True)
        
        # Get the current commit (local) and remote commit (from the main branch)
        local_commit = subprocess.check_output(['git', 'rev-parse', 'HEAD']).strip()
        remote_commit = subprocess.check_output(['git', 'rev-parse', 'origin/main']).strip()

        if local_commit != remote_commit:
            print("New updates are available.")
            updates_info = get_update_info()
            if updates_info:
                print("Available updates:\n", updates_info)
            
            user_input = input("Do you want to download and apply the updates? (yes/y to continue, no/n to cancel): ").strip().lower()
            if user_input in ['yes', 'y']:
                print("Pulling updates...")
                subprocess.run(['git', 'pull', 'origin', 'main'], check=True)
                print("Updates successfully applied.")
            else:
                print("Update canceled by the user.")
        else:
            print("No updates available.")
    except subprocess.CalledProcessError as e:
        print("An error occurred during the update process:", e.stderr.decode())
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

# Main function
def main():
    try:
        if not is_git_repo():
            print("This is not a Git repository. Please make sure you're in a cloned repository.")
            return

        update_repo()
    except Exception as e:
        print(f"An unexpected error occurred in the main function: {e}")

if __name__ == "__main__":
    main()
