#!/usr/bin/python3

"""
Sandboxes code execution
"""

from base64 import b64encode
from os.path import join, isfile
from subprocess import Popen, run, PIPE, TimeoutExpired
from tempfile import TemporaryDirectory
from typing import List
from xvfbwrapper import Xvfb
from signal import SIGINT

from codesandbox.typings import Files, TestResult

TIMEOUT = 4
ENTRYPOINT = "test.py"
PYTHON_EXEC = "python3"
FIREJAIL_EXEC = "firejail"

def get_firejail_kill_args(tmp_file: str) -> List[str]:
    """ Gets the firejail args to kill a sandbox """

    return [
        FIREJAIL_EXEC,
        "--shutdown={}".format(tmp_file)
    ]

def get_firejail_args(tmp_path: str, tmp_file: str) -> List[str]:
    """ Gets the firejail command to run """

    return [
        FIREJAIL_EXEC,
        "--private={}".format(tmp_path),
        "--quiet",
        "--private-dev",
        "--name={}".format(tmp_file),
        PYTHON_EXEC,
        ENTRYPOINT
    ]

def get_x11_firejail_args(tmp_path: str, tmp_file: str) -> List[str]:
    """ Gets the x11 firejail parameters """

    args = get_firejail_args(tmp_path, tmp_file)

    # Append the x11 flag
    args.append("--x11")

    return args

def write_files(tmp_path: str, files: Files):
    """ Writes a dictionary containing a mapping of filenames to contents
    to the given path
    """

    for filename in files.keys():
        full_path = join(tmp_path, filename)

        with open(full_path, "w") as tmp_file:
            tmp_file.write(files[filename])

def run_code(files: Files) -> TestResult:
    """
    Securely runs code within a sandbox in a temp directory

    The temp directory is automatically removed when the function exits
    """
    with TemporaryDirectory() as tmp:
        write_files(tmp, files)

        tmp_file = tmp.split("/")[-1]

        args = get_firejail_args(tmp, tmp_file)

        with Popen(args, stdout=PIPE, stderr=PIPE) as proc:
            try:
                proc.wait(TIMEOUT)

                result = TestResult()
                result.stdout = proc.stdout.read().decode()
                result.stderr = proc.stderr.read().decode()
                result.exitCode = proc.returncode

                img_path = join(tmp, "output.png")


                # Check if it creates an image (matplotlib)
                if isfile(img_path):
                    img_data = ""
                    with open(img_path, "rb") as img:
                        img_data = b64encode(img.read())

                    result.img = img_data.decode()

                return result

            except TimeoutExpired:
                proc.terminate()
                proc.wait()

                result = TestResult()
                # TODO: Figure out how to get stdout from this
                result.stdout = ""
                result.stderr = "Code did not finish, possible infinite loop"
                result.exitCode = 1

                return result


def run_gui_code(files: Files):
    """
    Securely runs code within a sandbox in a temp directory

    The temp directory is automatically removed when the function exits
    """
    with TemporaryDirectory() as tmp:

        tmp_file = tmp.split("/")[-1]

        result = TestResult()
        write_files(tmp, files)

        with Xvfb() as display:
            # Launch the tkinter problem
            display_num = display.new_display
            args = get_x11_firejail_args(tmp, tmp_file)
            print(" ".join(args))

            with Popen(args, stdout=PIPE, stderr=PIPE) as proc:
                try:
                    stdout, stderr = proc.communicate(timeout=TIMEOUT)

                    # Catch syntax errors
                    result = TestResult()
                    result.stdout = stdout.decode()
                    result.stderr = stderr.decode()
                    result.exitCode = proc.returncode

                    return result

                except TimeoutExpired:
                    # Capture the screen
                    img_path = join(tmp, "output.jpg")
                    run("DISPLAY=:{} import -window root -trim {}"
                        .format(display_num, img_path), shell=True)

                    img_data = ""
                    with open(img_path, "rb") as img:
                        img_data = b64encode(img.read())

                    run(["firejail", "--list"])

                    # Kill the child if it doesn't exit automatically
                    kill_cmd = get_firejail_kill_args(tmp_file)
                    print(" ".join(kill_cmd))
                    run(kill_cmd)
                    stdout, stderr = proc.communicate()

                    result.img = img_data.decode()
                    result.stdout = stdout.decode()
                    result.stderr = stderr.decode()
                    result.exitCode = proc.returncode

                    # Fix for old mypy gui questions, ensuring all tests
                    # are correct. Exit code 15 is always received
                    result_iterator = result.stdout.strip().split("},")
                    correct_attempt = True
                    for test in result_iterator:
                        if test.find('"correct": true') == -1:
                            correct_attempt = False
                    if (correct_attempt or result.stdout.strip() == "[]") and result.exitCode == 15:
                        result.exitCode = 0

                    print(result.stdout)
                    print(result.exitCode)

    return result
