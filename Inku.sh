#!/bin/bash

# Function to print error messages in red
error_exit() {
    echo -e "\e[31m$1\e[0m" 1>&2
    exit 1
}

# Hardcoded MySQL user details
MYSQL_USER="IncognitoVault"
MYSQL_PASSWORD="IV_2024"

# Capture the script's initial directory
SCRIPT_DIR="$(pwd)"

# Greet the user and introduce the assistant
echo -e "\e[34mHey! I am Inku, your Assistant in Incognito-Vault 🕵️‍♂️💻\e[0m"
sleep 2
echo -e "\e[33mStarting Server Configuration... ⏳\e[0m"
sleep 5

# 1. MySQL Setup
echo -e "\e[36mStep 1: Setting up MySQL Server... 🔧\e[0m"
if ! command -v mysql >/dev/null 2>&1; then
    echo -e "\e[33mMySQL not found. Installing... 🛠️\e[0m"
    sudo apt update || error_exit "Failed to update package list."
    sudo apt install -y mariadb-server mariadb-client || error_exit "Failed to install MySQL."
else
    echo -e "\e[32mMySQL is already installed. ✅\e[0m"
fi

echo -e "\e[33mEnabling and starting MySQL service... 🔄\e[0m"
sudo systemctl enable mariadb || error_exit "Failed to enable MySQL service."
sudo systemctl start mariadb || error_exit "Failed to start MySQL service."

echo -e "\e[36mChecking if MySQL user '${MYSQL_USER}' exists... 🔍\e[0m"
USER_EXISTS=$(sudo mysql -u root -sse "SELECT EXISTS(SELECT 1 FROM mysql.user WHERE user = '${MYSQL_USER}');")

if [ "$USER_EXISTS" -eq 1 ]; then
    echo -e "\e[32mMySQL user '${MYSQL_USER}' already exists. Skipping user creation. 👌\e[0m"
else
    echo -e "\e[33mCreating MySQL user '${MYSQL_USER}' and granting privileges... 🛡️\e[0m"
    sudo mysql -u root -e "
    CREATE USER '${MYSQL_USER}'@'localhost' IDENTIFIED BY '${MYSQL_PASSWORD}';
    GRANT ALL PRIVILEGES ON *.* TO '${MYSQL_USER}'@'localhost' WITH GRANT OPTION;
    FLUSH PRIVILEGES;
    " || error_exit "Failed to create MySQL user or grant privileges."
    echo -e "\e[32mMySQL user '${MYSQL_USER}' created successfully. 🎉\e[0m"
fi

# 2. Redis Setup
echo -e "\e[36mStep 2: Setting up Redis Server... 🧑‍💻\e[0m"
if ! command -v redis-server >/dev/null 2>&1; then
    echo -e "\e[33mRedis not found. Installing... 🛠️\e[0m"
    sudo apt update || error_exit "Failed to update package list."
    sudo apt install -y redis-server || error_exit "Failed to install Redis."
else
    echo -e "\e[32mRedis is already installed. ✅\e[0m"
fi

echo -e "\e[33mEnabling and starting Redis service... 🔄\e[0m"
sudo systemctl enable redis-server || error_exit "Failed to enable Redis service."
sudo systemctl start redis-server || error_exit "Failed to start Redis service."

echo -e "\e[32mRedis server is up and running. 🚀\e[0m"

# 3. Python Virtual Environment
echo -e "\e[36mStep 3: Setting up Python Virtual Environment... 🐍\e[0m"
VENV_DIR=".venv"
if [ -d "${VENV_DIR}" ]; then
    echo -e "\e[32mVirtual environment '${VENV_DIR}' already exists. Skipping creation. 👌\e[0m"
else
    echo -e "\e[33mCreating virtual environment in '${VENV_DIR}'... 🔧\e[0m"
    python3 -m venv "${VENV_DIR}" || error_exit "Failed to create virtual environment."
fi

echo -e "\e[33mActivating the virtual environment... 🔑\e[0m"
source "${VENV_DIR}/bin/activate" || error_exit "Failed to activate virtual environment."

echo -e "\e[33mInstalling dependencies... 📦\e[0m"
if [ -f "${SCRIPT_DIR}/requirements.txt" ]; then
    pip install -r "${SCRIPT_DIR}/requirements.txt" || error_exit "Failed to install Python dependencies."
    echo -e "\e[32mDependencies installed successfully. ✅\e[0m"
else
    echo -e "\e[33mrequirements.txt not found. Skipping dependency installation. ⚠️\e[0m"
fi
deactivate

# 4. Ask user if they want to start the server now
echo -e "\e[32mServer setup completed! 🎉\e[0m"
echo -e "\e[36mWould you like to start the server now? (yes/y, no/n)? 🤔\e[0m"
read -p "Enter your choice: " USER_CHOICE

if [[ "$USER_CHOICE" == "yes" || "$USER_CHOICE" == "y" ]]; then
    echo -e "\e[33mGreat! Let's proceed to start the server... 🔥\e[0m"

    # Ask user to choose server type
    echo -e "\e[36mChoose how you want to start the server:\e[0m"
    echo -e "\e[33m1. Flask Server 🐍\e[0m"
    echo -e "\e[33m2. uWSGI Server 🖥️\e[0m"
    echo -e "\e[33m3. Manually start the server 🛠️\e[0m"
    read -p "Enter your choice (1/2/3): " SERVER_CHOICE

    case $SERVER_CHOICE in
    1)
        echo -e "\e[33mStarting Flask server... 🚀\e[0m"
        source "${VENV_DIR}/bin/activate" || error_exit "Failed to activate virtual environment."
        python app.py || error_exit "Failed to start Flask server."
        deactivate
        ;;
    2)
        echo -e "\e[33mSetting up uWSGI server... ⚙️\e[0m"
        source "${VENV_DIR}/bin/activate" || error_exit "Failed to activate virtual environment."
        if ! pip show uwsgi >/dev/null 2>&1; then
            pip install uwsgi || error_exit "Failed to install uWSGI."
        fi
        uwsgi --ini uwsgi.ini || error_exit "Failed to start uWSGI server."
        deactivate
        ;;
    3)
        echo -e "\e[32mOkay... Here's how you can start the server manually: 📝\e[0m"
        echo ""
        echo "To start the Flask server:"
        echo "1. Activate the virtual environment: source ${VENV_DIR}/bin/activate"
        echo "2. Run the application: python app.py"
        echo "3. Deactivate the virtual environment when done: deactivate"
        echo ""
        echo "To start the uWSGI server:"
        echo "1. Activate the virtual environment: source ${VENV_DIR}/bin/activate"
        echo "2. Ensure uWSGI is installed: pip install uwsgi"
        echo "3. Run the server using your uWSGI configuration: uwsgi --ini uwsgi.ini"
        echo "4. Deactivate the virtual environment when done: deactivate"
        echo ""
        echo -e "\e[32mGood luck! 🚀\e[0m"
        ;;
    *)
        echo -e "\e[31mInvalid choice. Exiting. ❌\e[0m"
        exit 1
        ;;
    esac
elif [[ "$USER_CHOICE" == "no" || "$USER_CHOICE" == "n" ]]; then
    echo -e "\e[32mYou can start the server manually later. Here's how: 📝\e[0m"
    echo ""
    echo "To start the Flask server:"
    echo "1. Activate the virtual environment: source ${VENV_DIR}/bin/activate"
    echo "2. Run the application: python app.py"
    echo "3. Deactivate the virtual environment when done: deactivate"
    echo ""
    echo "To start the uWSGI server:"
    echo "1. Activate the virtual environment: source ${VENV_DIR}/bin/activate"
    echo "2. Ensure uWSGI is installed: pip install uwsgi"
    echo "3. Run the server using your uWSGI configuration: uwsgi --ini uwsgi.ini"
    echo "4. Deactivate the virtual environment when done: deactivate"
    echo ""
    echo -e "\e[34mGoodbye! 👋\e[0m"
    exit 0
else
    echo -e "\e[31mInvalid choice. Exiting. ❌\e[0m"
    exit 1
fi
