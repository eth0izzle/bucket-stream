#!/bin/bash

docker run \
	-v $(pwd):/bucket-stream:rw \
	--name bucket-stream \
	--rm -d bucket-stream
