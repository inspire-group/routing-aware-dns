#!/bin/bash

# install dependencies and AWS tools
sudo apt update

sudo apt install jq
sudo apt install unzip
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install

sudo apt install python3-pip -y
pip3 install boto3
pip3 install dnspython

# install Github deploy key
GITHUB_RSA_FINGERPRINT="github.com ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ=="
echo $GITHUB_RSA_FINGERPRINT >> ~/.ssh/known_hosts
aws s3 cp s3://letsencryptdnsresults/cred/id_ed25519 ~/.ssh/id_ed25519
chmod 600 ~/.ssh/id_ed25519
eval `ssh-agent`
ssh-add ~/.ssh/id_ed25519
git clone git@github.com:birgelee/routing-aware-dns.git

# install Unbound backup resolver
sudo apt install unbound
sudo systemctl disable systemd-resolved --now