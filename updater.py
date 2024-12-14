import os
import sys
from git import Repo, GitCommandError

# Determine the current platform
platform = sys.platform

# Check if the current directory is a Git repository
def is_git_repo():
    try:
        repo = Repo('.')
        return not repo.bare
    except GitCommandError:
        return False
    except Exception as e:
        print(f"Error checking Git repository: {e}")
        return False

# Get the latest commit message and author for available updates
def get_update_info(repo):
    try:
        fetch_info = repo.remotes.origin.fetch()
        remote_branch = repo.remotes.origin.refs['main']
        commits = list(repo.iter_commits(f"HEAD..{remote_branch.name}"))
        if commits:
            updates_info = "\n".join(
                [f"{commit.hexsha[:7]} {commit.author.name}: {commit.message.strip()}" for commit in commits]
            )
            return updates_info
        return None
    except GitCommandError as e:
        print(f"Error retrieving update information: {e}")
        return None
    except Exception as e:
        print(f"Unexpected error while retrieving update info: {e}")
        return None

# Pull updates from the repository
def update_repo():
    try:
        repo = Repo('.')
        print("Fetching the latest changes from the remote repository...")
        repo.remotes.origin.fetch()

        # Get the current commit (local) and remote commit (from the main branch)
        local_commit = repo.head.commit.hexsha
        remote_commit = repo.remotes.origin.refs['main'].commit.hexsha

        if local_commit != remote_commit:
            print("New updates are available.")
            updates_info = get_update_info(repo)
            if updates_info:
                print("Available updates:\n", updates_info)

            user_input = input("Do you want to download and apply the updates? (yes/y to continue, no/n to cancel): ").strip().lower()
            if user_input in ['yes', 'y']:
                print("Pulling updates...")
                repo.remotes.origin.pull('main')
                print("Updates successfully applied.")
            else:
                print("Update canceled by the user.")
        else:
            print("No updates available.")
    except GitCommandError as e:
        print(f"An error occurred during the update process: {e}")
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
