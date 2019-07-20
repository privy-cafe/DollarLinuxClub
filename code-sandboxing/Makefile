lint:
	python3 -m pylint codesandbox

test:
	pip3 install -e .
	python3 codesandbox/*_test.py

dev:
	pip3 install -e .
	FLASK_APP=codesandbox FLASK_DEBUG=true flask run --host=0.0.0.0 --port=8000
