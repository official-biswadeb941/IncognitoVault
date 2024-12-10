```bash

Incognito-Vault Version: 1.0.0 — Redefining security for business, professionals and students. Trust, Innovations & Security. (Powered by ParseSphere Innovations).
│
├── templates/
│   ├── auth.html                 # Login Form
│   ├── Error-Page/               # Contain Error Pages
│   └── Super-Admin/              # Contain HTML Templates For Super Admin Template
│       ├── Base/
│       │   └── SA.html           # Main template for Incognito Vault Super Admin 
│       ├── dashboard.html        # Template for dashboard page
│       ├── database.html         # Template for database
│       ├── documentation.html    # Template for documentation
│       ├── form.html             # Template for form 
│       ├── logs.html             # Template for logs
│       └── settings.html         # Template for settings
│ 
├── Database/
│   ├── Config                    # Contain User Credentials
│   ├── mysql.json                # Contain Mysql Credentials
│   └── Super-Admin/              # Contain Redis Credentials
│
├── static/
│   ├── css/                      # CSS files
│   │   ├── auth.css              # Login Form CSS
│   │   ├── error-page.css        # Error-Page CSS
│   │   └── SA.css                # Contain all CSS for Dashboard, database, etc.
│   ├── js/                       # JavaScript files
│   │   ├── auth.js               # Login Form JS
│   │   ├── alive.js              # JS function for alive function
│   │   └── SA.js                 # Contain all JS for Dashboard, database, etc.
│   └── images/                   # Images
│
├── Modules/
│   ├── __init__.py               # Initialize Module
│   ├── captcha_manager.py        # Captcha Manager
│   ├── db_manager.py             # Database Manager
│   ├── error_handler.py          # Error Handler
│   ├── lock_manager.py           # LockOut Manager
│   ├── rate_limit.py             # Rate Limiter
│   ├── redis_manager.py          # Redis Manager
│   ├── session_manager.py        # Session Manager
│   ├── form.py                   # custom form code
│   ├── api.py                    # API Endpoint
│   └── version.py                # Contains Version
│
├── app.py                        # Main application entry point
├── .gitignore                    # Gitignore
├── requirements.py               # Library Requirement 
├── Database                      # Database configuration file
├── Projects.md                   # Documentation
├── Database                      # Database configuration file
├── Database                      # Database configuration file
├── Audit_Report.md               # Audit report configuration file
├── LICENSE                       # License
├── CHNAGELOG.md                  # Version Control
└── README.md                     # Readme file

```