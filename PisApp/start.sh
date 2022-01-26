#!/bin/bash

python3 -u /code/webapp/protocol/merchantserver.py &
python3 -u /code/webapp/protocol/clientserver.py &

gunicorn -b 0.0.0.0:5001 wsgi:app &

# Wait for any process to exit
wait -n
  
# Exit with status of process that exited first
exit $?