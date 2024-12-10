# Incognito-Vault  
`Developed & licensed by ParseSphere Innovation.`

Incognito-Vault is a secure, scalable, and feature-rich platform designed to streamline database management, logging, and forms for both office and student needs, with robust security features and an intuitive interface.  

## Version Information
- **Current Version**: `v1.0.0`
- **Release Date**: December 3, 2024

---

## Table of Contents  
1. [Features](#features)  
2. [Security Features](#security-features)  
3. [Project Structure](#project-structure)  
4. [Documentation](#documentation)  
5. [Production Deployment](#production-deployment)  
6. [Usage](#usage)  
7. [Contributing](#contributing)  
8. [License](#license)  
9. [Contact](#contact)  


---

## Features  
- **Secure User Authentication**: Login system with rate-limiting and lockout mechanisms.  
- **Super Admin Dashboard**: Comprehensive admin panel with features for database management, logs, and settings.  
- **Error Handling**: User-friendly error pages and robust backend error handling.  
- **Documentation**: Clear and detailed project documentation for ease of use.  
- **Responsive Design**: All templates are optimized for different screen sizes.  
- **Modular Codebase**: Clean, modular code for easy maintenance and scalability.
- **Robust Security**: Robust protections against malicious code that affects performance and security vulnerabilities of the server. This application is designed to protect your data from both traditional and advanced hacking attacks
---

## Security Features  

Incognito-Vault ensures the highest level of security through the following features:  

1. **Rate Limiting**  
   - Protects against brute-force attacks by limiting the number of login attempts.  

2. **Lockout Mechanism**  
   - Temporarily locks accounts after multiple failed login attempts to prevent unauthorized access.  

3. **Captcha Verification**  
   - Prevents automated attacks with integrated CAPTCHA on login forms.  

4. **Session Management**  
   - Implements secure user session handling to prevent session hijacking.  

5. **Redis-Powered Backend**  
   - Fast and secure data caching and session management using Redis.  

6. **Error Handling and Logging**  
   - Graceful error pages and detailed server-side logging to monitor and address security issues promptly.  

7. **Secure Authentication**  
   - Encrypted passwords and secure login protocols ensure user credentials are safeguarded.  

8. **HTTPS Ready**  
   - Supports secure communication with HTTPS encryption. (Only if Deployed in production environment like VPS server or cloud server in Hostinger or Amazon AWS).

9. **Security Audit**
   - A detailed Security Audit Report is available to ensure transparency and continued improvements.
   - The report is accessible in the root directory or Visit [Audit.md](Audit_Report.md) .


## Project Structure  

For detailed information on the project structure and modules, refer to the [Project Documentation](Project.md).  


## Production Deployment  

To deploy **Incognito-Vault** in a production environment, follow these steps:

### 1. Prerequisites  

## System Requirements

- **Operating System**:
  - Linux (e.g., Ubuntu 20.04+ or CentOS 7+) (For Production Environment)
  - macOS (for development only)
  - Windows 10/11 (WSL2 recommended for development)

- **Memory**:
  - Minimum: 2 GB RAM
  - Recommended: 4+ GB RAM

- **Disk Space**:
  - Minimum: 20 GB free
  - Recommended: 50 GB free

- **CPU**:
  - 64-bit processor
  - Multi-core recommended for better performance

---

## Server Setup Configurations

- Python 3.8+
- Python Virtual Environment
- A production-ready WSGI server (e.g., **uWSGI**)
- Redis installed and configured
- Mysql installed and configured
- Nginx or Apache as a reverse proxy (optional but recommended)



- **Virtual Environment Creation &  Configuration**:  
  - Create a virtual environment

    ```bash
    python -m venv .venv
    ```
  - Activate the virtual environment

    ```bash
    source .venv/bin/activate
    ```
  - Set environment variables for database credentials, Redis, and Flask settings (e.g., `FLASK_ENV=production`).  

---
### 2. Install Dependencies  
 - Make sure all required dependencies are installed: 

    ```bash
    pip install -r requirements.txt
    ```
---
### 3. Configure the Application

- **Update Configuration Files**:
  - Edit the database configuration in the `Database/` directory.
  - Ensure Redis settings in `Modules/redis_manager.py` are correct for your production environment.

---

### 4. Use UWSGI for WSGI Server

- Run the application using **uWSGI**:

    ```bash
    uwsgi --ini uwsgi.ini
    ```
---

### `5. Having Problem with Installation!! Getting Error!! Don't Know from Where to start!!.`

- Feel free to call Inku Assistant, Your very own assistant in Incognito-Vault and it will solve all the above problems.
     
     - Give necessary permissions to Inku Assistant.

        ```bash
        chmod +x Inku.sh
        ```
     - Call Inku Assistant for Server Setup.

        ```bash
        ./Inku.sh
        ```
        
---

### 6. Configure Reverse Proxy (Optional but Recommended)
 - Use Nginx to serve as a reverse proxy to forward requests to Gunicorn. Example Nginx configuration:

    ```bash
        server {
            listen 80;
            server_name yourdomain.com;

            location / {
                proxy_pass http://127.0.0.1:8000;
                proxy_set_header Host $host;
                proxy_set_header X-Real-IP $remote_addr;
                proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                proxy_set_header X-Forwarded-Proto $scheme;
            }

            error_page 500 502 503 504 /50x.html;
            location = /50x.html {
                root /usr/share/nginx/html;
            }
        }
    ```
- Restart Nginx to apply the configuration:

    ```bash
        sudo systemctl restart nginx
    ```
---

### 6. Enable HTTPS (Optional but Recommended)
- Use Let's Encrypt or another SSL provider to secure your application. For Let's Encrypt:

    ```bash
    sudo apt install certbot python3-certbot-nginx
    sudo certbot --nginx -d yourdomain.com
    ```
---

### 7. Background Tasks (Redis Setup)
- Ensure Redis is running:

    ```bash
    sudo systemctl start redis
    sudo systemctl enable redis
    ```
    - Verify Redis Installation:
    - To confirm Redis is correctly installed and running, use the following commands:

    ```bash
    redis-cli ping
    ```
 - If Redis is running, it will return:

    ```bash
     PONG
    ```
    ### Securing Redis:

    For a production environment, follow these steps to secure Redis:

    1. Bind Redis to localhost (to prevent external access): Edit the Redis configuration file (usually located at `/etc/redis/redis.conf)`:

        ```bash
        bind 127.0.0.1
        ```
    2. Require a Password: Uncomment and set a strong password in the same configuration file:

        ```bash
        requirepass your-strong-password
        ```

    3. Restart Redis to apply changes:

        ```bash
        sudo systemctl restart redis
        ```

    ### Monitor Redis Performance:

    To monitor Redis logs and performance:

    - Check Logs
        ```bash
        sudo journalctl -u redis
        ```
    - Use the `INFO` command to see details about memory usage, connections, and more:

        ```bash
        redis-cli INFO
        ```

    By following these steps, you ensure that Redis is not only running but also secure and optimized for `Production use`. This addition includes security measures and monitoring tips that are essential for a `Reliable Production Setup`.

---

### Usage

After setting up your Incognito-Vault platform, you can start using it by accessing the application through your web browser.

### 1. Logging In
- Visit the application’s homepage (e.g., http://yourdomain.com).
- Use the provided login credentials (set during setup or in the database) to log in.
- After successful login, you will be redirected to your dashboard based on your user role (admin or regular user).
### 2. Accessing the Admin Dashboard
- Admin users will have access to the Super Admin Dashboard.
- From the dashboard, you can manage users, view logs, and perform various administrative tasks, such as:
    - Managing User Accounts: Add, remove, or modify user accounts.
    - Database Management: View and modify the application’s database through the Admin panel.
    - Log Monitoring: View activity logs to track usage and detect any issues.
### 3. Managing Databases
- Access the Database Management section to add or modify entries.
- The platform supports structured templates for managing forms, queries, and logging.
### 4. Error Logs and Notifications
- If errors occur, the platform logs them securely for admin review.
- Admins are notified in real-time via error handling and logging features integrated into the platform.

---

### Contributing
We welcome contributions from the community! Here’s how you can get involved in improving Incognito-Vault:

1. Fork the Repository
   - Fork the Incognito-Vault repository on GitHub to create your own copy.
2. Clone Your Fork
   - Clone the repository to your local machine:

        ```bash
        git clone https://github.com/your-username/incognito-vault.git
        ```
3. Create a Feature Branch
    - Create a new branch for your feature or bug fix:

        ```bash
        git checkout -b feature/your-feature-name
        ```
4. Make Changes
    - Implement your changes locally.
    - Make sure to follow the project’s coding conventions and run tests.
5. Commit and Push Changes
    - After implementing your changes, commit them to your local branch:

        ```bash
        git add .
        git commit -m "Description of the changes"
        git push origin feature/your-feature-name
        ```
6. Create a Pull Request
    - Go to the Incognito-Vault GitHub page and create a pull request from your feature branch.
    - Provide a detailed description of the changes you've made.
7. Review Process
    - Your pull request will be reviewed by the project maintainers.
    - You may be asked to make additional changes based on the feedback.

---

### License
This project is licensed under the `Incognito-Vault Attribution & Compliance License (IVACL)`.

By using, modifying, or distributing this software, you agree to comply with the terms outlined in the license, including proper attribution to `ParseSphere Innovations`.

For full details, refer to the [LICENSE](License.md) file included in this repository.  

---

###  Contact  

For any questions, licensing inquiries, or permissions, please reach out to:  

**ParseSphere Innovation**  
- **Email**: [parsesphereinnovations@gmail.com](mailto:parsesphereinnovations@gmail.com)
- **Website**: [https://cutt.ly/parsephere-innovations](https://cutt.ly/parsephere-innovations)  
- **Address**: Sodepur, Kolkata

We value your feedback and inquiries regarding **Incognito-Vault** and aim to respond promptly.

