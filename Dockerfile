# - build with `docker build --tag full-graph-dns-resolver .`
# - start the container in the background `docker run --name dns-resolver -d full-graph-dns-resolver`
# - execute bash in the container `docker exec -it dns-resolver bash`
# - perform dns lookups from within the container with `./log_processor_artifact.py`
# - check running status `docker ps`
# - kill the background container `docker kill dns-resolver`

FROM ubuntu:jammy

RUN apt-get update && apt-get install -y \
    git \
    python3 \
    dos2unix \
    python3-pip \
    vim \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install dnspython

WORKDIR routing-aware-dns
RUN git init -q && git remote add origin https://github.com/inspire-group/routing-aware-dns.git
RUN git fetch -q origin && git checkout -q usenix-23-artifact
RUN dos2unix log_processor_artifact.py
RUN mkdir output
CMD tail -f /dev/null
