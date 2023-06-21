# - build with `docker build --tag full-graph-dns-resolver .`
# - run interactive container with `docker run -it --entrypoint /bin/bash full-graph-dns-resolver`
# - perform dns lookups from within the container with `./log_processor_artifact.py`

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
ENTRYPOINT ["tail -f"]
CMD ["--help"]
