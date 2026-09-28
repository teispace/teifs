# boto3, the AWS SDK for Python, in a virtual environment of its own.
source "$HERE/lib.sh"
VENV="$CLIENT_WORK/../boto3-venv"
[ -x "$VENV/bin/python" ] || python3 -m venv "$VENV"
"$VENV/bin/pip" install --quiet --requirement "$HERE/boto3/requirements.txt"
make_data
"$VENV/bin/python" "$HERE/boto3/check.py"
