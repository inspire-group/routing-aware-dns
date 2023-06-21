# - build with `docker build --tag full-graph-dns-resolver .`
# - run interactive container with `docker run -it --entrypoint /bin/bash full-graph-dns-resolver`
# - execute simulation from within the container with `/routing-aware-dns/ --topology_file data/topo/20210401.as-rel2.txt --origins_file data/origins/origins-sbas-k100adv.800.txt --policies_file data/policies/policies-sbas-victims.txt

FROM ubuntu:jammy

RUN apt-get update && apt-get install -y \
    git \
    python3 \
    dos2unix \
    python3-pip \
    vim \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install matplotlib netaddr numpy

WORKDIR routing-aware-dns
RUN git init -q && git remote add origin https://github.com/inspire-group/routing-aware-dns.git
RUN git fetch -q origin && git checkout -q usenix-23-artifact
RUN dos2unix /sbas-simulation/code/simulate.py
ENTRYPOINT ["/sbas-simulation/code/simulate.py"]
CMD ["--help"]
