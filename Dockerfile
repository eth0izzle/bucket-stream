FROM python:3
#
# Build Container:
# $ docker build -t bucket-stream .
#
# Run:
# $ docker run -it --rm --name bucket-stream -v `pwd`:/usr/src/app bucket-stream
#
WORKDIR /usr/src/app

COPY requirements.txt ./

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD [ "python", "./bucket-stream.py" ]
