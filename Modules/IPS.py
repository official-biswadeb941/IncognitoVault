import socket
import requests

class IPAddress:
    def __init__(self):
        self.private_ip = self._get_private_ip()
        self.public_ip = self._get_public_ip()

    def _get_private_ip(self):
        """Retrieve the private IP address of the machine."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            private_ip = s.getsockname()[0]
            s.close()
            return private_ip
        except Exception as e:
            return f"Error retrieving private IP: {e}"

    def _get_public_ip(self):
        """Retrieve the public IP address of the machine."""
        try:
            response = requests.get("https://api.ipify.org?format=text")
            if response.status_code == 200:
                return response.text
            else:
                return f"Error retrieving public IP: {response.status_code}"
        except Exception as e:
            return f"Error retrieving public IP: {e}"

    def get_ips(self):
        """Return both private and public IP addresses."""
        return {
            "private_ip": self.private_ip,
            "public_ip": self.public_ip
        }
    
IPS = IPAddress()

