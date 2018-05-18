FROM python:3.7-rc-alpine

COPY ./requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

VOLUME /bucket-stream
WORKDIR /bucket-stream

CMD ["python3", "bucket-stream.py", "--ignore-rate-limiting", "--log", "-t 2"]
