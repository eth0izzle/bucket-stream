from python:alpine3.6

RUN set -ex; \
    addgroup -g 1000 bucketstream; \
    adduser -D -u 1000 -G bucketstream bucketstream;

ADD . /home/bucketstream/

WORKDIR /home/bucketstream

RUN pip3 install -r requirements.txt

USER bucketstream

ENTRYPOINT ["python3", "bucket-stream.py"]
