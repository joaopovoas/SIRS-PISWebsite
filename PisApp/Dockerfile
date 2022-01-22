# syntax=docker/dockerfile:1
FROM ubuntu
WORKDIR /code
ENV FLASK_APP=webapp/__init__.py
ENV FLASK_RUN_HOST=0.0.0.0
# this enables debugging and automatic reloading:
# ENV FLASK_ENV=development

RUN apt-get update
RUN apt-get install mysql-client -y
RUN apt-get install libmysqlclient-dev mysql-server -y
# This issue might be related to memory available for Docker:
# https://stackoverflow.com/a/68741096/12865378
RUN apt-get install pip -y; exit 0
COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt

EXPOSE 5001
EXPOSE 8765
COPY . .
RUN chmod +x /code/start.sh
CMD ["/code/start.sh"]
# python3 /code/webapp/server.py
# gunicorn -b 0.0.0.0:5000 wsgi:app
