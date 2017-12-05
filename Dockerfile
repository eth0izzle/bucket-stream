FROM python:3
MAINTAINER Dave (Daviey) Walker <email@daviey.com>

WORKDIR /opt

COPY *.py *.yaml *.txt /opt/
COPY requirements.txt /opt/

RUN pip3 install -r /opt/requirements.txt

ENTRYPOINT ["/usr/local/bin/python", "bucket-stream.py"]

