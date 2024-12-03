import os
import subprocess
import sys

# Determine the current platform
platform = sys.platform

# Check if the current directory is a git repository
def is_git_repo():
    return subprocess.call(['git', 'rev-parse', '--is-inside-work-tree'], stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0

# Pull updates from the repository
def update_repo():
    print("Fetching the latest changes from the remote repository...")
    subprocess.run(['git', 'fetch', 'origin'], check=True)

    # Get the current commit (local) and remote commit (from the main branch)
    local_commit = subprocess.check_output(['git', 'rev-parse', 'HEAD']).strip()
    remote_commit = subprocess.check_output(['git', 'rev-parse', 'origin/main']).strip()

    if local_commit != remote_commit:
        print("New updates available. Pulling changes...")
        subprocess.run(['git', 'pull', 'origin', 'main'], check=True)
    else:
        print("No updates available.")

# Main function
def main():
    if not is_git_repo():
        print("This is not a Git repository. Please make sure you're in a cloned repository.")
        return

    update_repo()

if __name__ == "__main__":
    main()
