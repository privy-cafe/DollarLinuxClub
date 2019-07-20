"""
The REST api server for the coderunner

@author eLIPSE
"""

from json import dumps
from os import environ
from typing import Dict
from flask import Flask, request

from codesandbox.sandbox import run_code, run_gui_code
# Load environment variables
import codesandbox.settings

API_KEY = environ.get("API_KEY")

app = Flask(__name__)

def validate_request(req: Dict) -> bool:
    """ Validates the user's request """

    assert req is not None, "no JSON payload"

    # Check that the files are there
    assert "files" in req, "no 'files' field in payload"

    # Check that the gui flag is there
    assert "isGui" in req, "no 'isGui' field in payload"

    assert "apiKey" in req, "no 'apiKey' field in payload"

    # Check the api key is correct
    assert req["apiKey"] == API_KEY, "apiKey is incorrect"

def generate_error_response(message: str) -> Dict:
    """ Generates an error message to send over the send over the API

    Will send it with a 400 status code
    """

    return dumps({
        "msg": message
    }), 400



@app.route("/run", methods=["POST"])
def run():
    """
    The payload should take the form of:

        {
            "files": {
                "test.py": "print('Hello world')"
            },
            "isGui": false
        }
    """
    try:
        validate_request(request.get_json())
    except AssertionError as error:
        return generate_error_response(str(error))


    req = request.get_json()
    files = req["files"]
    isGui = req["isGui"]

    if isGui:
        app.logger.info("Executing GUI code")
        return dumps(run_gui_code(files).serialize())

    app.logger.info("Executing normal code")
    return dumps(run_code(files).serialize())
