Incognito-Vault   -------------   One of the most secure website for Office Works, Student Works, etc. (Made By ParseSPhere Innovation.)
│
├── Blueprints/
│   ├── __init__.py               # Initializes the blueprints folder
│   ├── auth.py                   # Handles authentication (login, logout, captcha)
│   ├── dashboard.py              # Contains routes for the dashboard
│   ├── database.py               # Routes for database interactions
│   ├── forms.py                  # Form-related routes
│   ├── logs.py                   # Log-related routes
│   ├── settings.py               # Settings management routes
│   ├── errors.py                 # Error handling routes (403, 404, 500, etc.)
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
│   ├── caching.py                # Custom caching functions
│   ├── captcha.py                # Custom CAPTCHA generation and validation
│   ├── session.py                # Session management functions
│   └── form.py                   # custom form code
│
├── app.py                        # Main application entry point
├── config.py                     # Configuration settings
├── .gitignore                    # Gitignore
├── requirements.py               # Library Requirement 
├── Database                      # Database configuration file
├── Projects.md                   # Documentation
└── README.md                     # Readme file
