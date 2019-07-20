"""
Loads the dotenv file

@author eLIPSE
"""
from dotenv import load_dotenv, find_dotenv

if load_dotenv(find_dotenv()) != True:
    print("Failed to find dotenv")
