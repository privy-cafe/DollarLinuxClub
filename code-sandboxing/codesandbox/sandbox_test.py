"""
Tests the sandbox module
"""

from base64 import b64encode
from unittest import TestCase, main
from codesandbox.sandbox import run_code, run_gui_code

class TestSandbox(TestCase):
    """ Test the sandbox code execution """

    def test_basic(self):
        """ Tests basic code running """
        files = {
            "test.py": "print('Hello world')",
        }

        output = {
            "stdout": "Hello world\n",
            "stderr": "",
            "exitCode": 0,
            "img": None
        }

        result = run_code(files)

        self.assertEqual(result.serialize(), output)

    def test_import(self):
        """ Tests importing other modules """

        files = {
            "test.py": "import file2\nprint('Hello world')",
            "file2.py": "print('File2')",
        }

        output = {
            "stdout": "File2\nHello world\n",
            "stderr": "",
            "exitCode": 0,
            "img": None
        }

        result = run_code(files)

        self.assertEqual(result.serialize(), output)

    def test_infinite_loop(self):
        """ Tests that infinite loops are terminated """
        files = {
            "test.py": "print('test')\nwhile 1:\n\tcontinue"
        }

        output = {
            "stdout": "",
            "stderr": "Code did not finish, possible infinite loop",
            "exitCode": 1,
            "img": None
        }

        result = run_code(files)

        self.assertEqual(result.serialize(), output)

    def test_networking(self):
        """ Tests that scripts cannot access the internet """

        script_contents = ""
        with open("./codesandbox/test_scripts/test_network.py", "r") as script:
            script_contents = script.read()

        files = {
            "test.py": script_contents,
        }


        result = run_code(files)

        # Should throw an exception and return nothing on stdout
        self.assertEqual(result.stdout, "")
        self.assertNotEqual(result.stderr, "")

class TestGuiSandbox(TestCase):
    """ Tests GUI sandboxing """

    def test_simple_gui(self):
        """ Tests a simple GUI """

        script_contents = ""
        with open("./codesandbox/test_scripts/sample_gui.py", "r") as script:
            script_contents = script.read()

        files = {
            "test.py": script_contents,
        }

        img_data = ""
        with open("./codesandbox/test_scripts/sample_gui_img_out", "r") as img:
            img_data = img.read().strip()

        result = run_gui_code(files)

        # Check to see if it produces the correct image
        self.assertEqual(result.img, img_data)

    def test_signal_handler(self):
        """ Tests signal handling with the GUI """

        script_contents = ""
        with open("./codesandbox/test_scripts/gui_with_signal.py", "r") as script:
            script_contents = script.read()

        files = {
            "test.py": script_contents,
        }

        img_data = ""
        with open("./codesandbox/test_scripts/sample_gui_img_out", "r") as img:
            img_data = img.read().strip()

        result = run_gui_code(files)

        # Check to see if it produces the correct image
        self.assertEqual(result.img, img_data)
        self.assertEqual(result.stdout, "Output from signal handler\n")

    def test_matplotlib(self):
        """ Tests a simple matplotlib plot """

        script_contents = ""
        with open("./codesandbox/test_scripts/test_matplotlib.py", "r") as script:
            script_contents = script.read()

        files = {
            "test.py": script_contents,
        }

        img_data = ""
        with open("./codesandbox/test_scripts/test_matplotlib_out.png", "rb") as img:
            img_data = b64encode(img.read()).decode()

        result = run_code(files)

        self.assertEqual(result.img, img_data)

if __name__ == "__main__":
    main()
