#!/bin/bash

REGION=$1

INSTNC_SIZE="t2.micro"
KEY_NM="le-logprocess-key"
KEY_ID="key-07c223021271b4dc3"
SG_ID="sg-0fc318c8761df6595"
IAM_ARN="arn:aws:iam::696090498373:instance-profile/LELogProcessing"
IAM_NM="LELogProcessing"

PRODUCT="server"
RELEASE="20.04"
ARCH="amd64"
VIRT_TYPE="hvm"
VOL_TYPE="ebs-gp2"

UBUNTU_CLOUD_IMAGES="ubuntu/$PRODUCT/$RELEASE/stable/current/$ARCH/$VIRT_TYPE/$VOL_TYPE/ami-id"
UBUNTU_AMI_NAME_PATH="/aws/service/canonical/$UBUNTU_CLOUD_IMAGES"

AMI_ID=`aws ssm get-parameters --names $UBUNTU_AMI_NAME_PATH --region $REGION | jq -r ".Parameters | .[] | .Value"`
echo $AMI_ID
echo 'got the AMI ID'

aws ec2 run-instances --image-id $AMI_ID --count 1 \
	--region $REGION\
	--instance-type $INSTNC_SIZE --key-name $KEY_NM \
	--security-group-ids $SG --iam-instance-profile "Arn=$IAM_ARN"\
	--user-data file://instance_setup.sh

exit 0