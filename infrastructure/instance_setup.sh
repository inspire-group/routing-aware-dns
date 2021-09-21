#!/bin/bash

UBUNTU_HOME="/home/ubuntu"
# install dependencies and AWS tools
apt update

apt install jq -y
apt install unzip
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
./aws/install

apt install python3-pip -y
pip3 install boto3
pip3 install dnspython

# install Github deploy key
su ubuntu <<'EOF'
cd $HOME
GITHUB_RSA_FINGERPRINT="github.com ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ=="
echo $GITHUB_RSA_FINGERPRINT >> ~/.ssh/known_hosts
aws s3 cp s3://letsencryptdnsresults/cred/id_ed25519 ~/.ssh/id_ed25519
chmod 600 ~/.ssh/id_ed25519
eval `ssh-agent`
ssh-add ~/.ssh/id_ed25519
git clone -b le_infra git@github.com:birgelee/routing-aware-dns.git
EOF

# install Unbound backup resolver
apt install unbound=1.9.4-2ubuntu1.2 -y
su -u unbound unbound-agent
mv /home/ubuntu/routing-aware-dns/infrastructure/unbound.conf /etc/unbound/unbound.conf
systemctl restart unbound

exit 0