import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # API Keys provided by user
    VT_API_KEY = os.getenv("VT_API_KEY", "3030bf0c2ec32e2a1570303d326ffe95021323fe92165cfd25ec91612cdebf56")
    GSB_API_KEY = os.getenv("GSB_API_KEY", "AIzaSyBwyXePU87fVv-ueO0rDPVxiXpQfIbRyz4")
    
    # Other settings
    TIMEOUT = 10  # Seconds for HTTP requests
