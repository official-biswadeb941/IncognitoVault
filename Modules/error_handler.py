# error_handlers.py
from flask import render_template
from werkzeug.exceptions import HTTPException
import logging


class ErrorHandler:
    def __init__(self, app):
        self.app = app
        
        # A dictionary mapping error codes to template files
        self.error_pages = {
            400: 'Error-Page/400-Bad-Request.html',
            401: 'Error-Page/401-Unauthorized.html',
            403: 'Error-Page/403-Forbidden.html',
            404: 'Error-Page/404-Not-Found.html',
            405: 'Error-Page/405-Method-Not-Allowed.html',
            408: 'Error-Page/408-Request-Timeout.html',
            409: 'Error-Page/409-Conflict.html',
            410: 'Error-Page/410-Gone.html',
            413: 'Error-Page/413-Large-Payload.html',
            415: 'Error-Page/415-Unsupported-Media-Type.html',
            418: 'Error-Page/418-Teapot.html',
            429: 'Error-Page/429-Many-Request.html',
            500: 'Error-Page/500-Internal-Server-Error.html',
            501: 'Error-Page/501-Not-Implemented.html',
            502: 'Error-Page/502-Bad-Gateway.html',
            503: 'Error-Page/503-Service-Unavailable.html',
            504: 'Error-Page/504-Gateway-Timeout.html',
            # Add more error pages as necessary
        }

        self.register_handlers()

    def register_handlers(self):
        for code in self.error_pages:
            self.app.errorhandler(code)(self.handle_error)
        self.app.errorhandler(Exception)(self.handle_exception)

    def handle_error(self, e):
        error_code = e.code if isinstance(e, HTTPException) else 500
        return self.render_error_page(error_code)

    def handle_exception(self, e):
        logging.exception(f"Unexpected error: {str(e)}")
        return self.render_error_page(500)

    def render_error_page(self, error_code):
        template = self.error_pages.get(error_code, 'Error-Page/default.html')
        logging.error(f"Rendering error page for {error_code}: {template}")
        return render_template(template), error_code

