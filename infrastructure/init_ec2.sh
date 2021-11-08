#!/bin/bash

REGION=$1
INSTANCE_SIZE=$2

KEY_NM="le-logprocess-key-$REGION"
IAM_ARN="arn:aws:iam::696090498373:instance-profile/LELogProcessing"
IAM_NM="LELogProcessing"

PRODUCT="server"
RELEASE="20.04"
ARCH="amd64"
VIRT_TYPE="hvm"
VOL_TYPE="ebs-gp2"


check_gen_key () {
	KEY_FILE="keys/$1.pem"
	if [[ ! -f $KEY_FILE ]]; then
		echo "Generating RSA key file $KEY_FILE"
		aws ec2 create-key-pair --key-name $1 --region $REGION | jq -r '.KeyMaterial' > $KEY_FILE
		aws ec2 wait key-pair-exists --key-names $1 --region $REGION
		chmod 600 $KEY_FILE
	else
		echo "Key $KEY_NM already present; using it"
	fi
}

get_default_vpc_desc () { 
	echo `aws ec2 describe-vpcs --filters "Name=is-default,Values=true" --region $REGION`
}

# steps to enable IPv6:
# 1. add IPv6 CIDR block to VPC
# 2. add IPv6 CIDR block to subnet(s)
# 3. add incoming/outgoing rules in security group
# 4. add entry in route table

configure_vpc_ipv6 () {
	echo "Associating IPv6 CIDR block with VPC ${VPC_ID}";

	aws ec2 associate-vpc-cidr-block --amazon-provided-ipv6-cidr-block \
									 --vpc-id $VPC_ID \
									 --region $REGION;
	
	aws ec2 wait vpc-available --vpc-ids $VPC_ID \
	--filters "Name=ipv6-cidr-block-association.state,Values=associated" \
	--region $REGION;
}

configure_subnet_ipv6 () {
	SUBNETS=`aws ec2 describe-subnets --region $REGION`
	SUBNET_IDS=(`echo $SUBNETS | jq -r ".Subnets[].SubnetId"`)

	IPV6_CIDR=`get_default_vpc_desc | jq -r ".Vpcs[].Ipv6CidrBlockAssociationSet[].Ipv6CidrBlock"`
	BLOCK=${IPV6_CIDR%00::*}
	PRFX_LEN_VPC=${IPV6_CIDR#*::/}
	let PRFX_LEN_SBNT=PRFX_LEN_VPC+8

	COUNTER=0

	for subnet in "${SUBNET_IDS[@]}"; do
		IS_SBNT_IPV6_ASSOC=`echo $SUBNETS\
					   | jq ".Subnets[]\
					   | select(.SubnetId == \"$subnet\")\
					   | .Ipv6CidrBlockAssociationSet
					   | length > 0 and .[].Ipv6CidrBlockState.State == \"associated\""`

		if [[ $IS_SBNT_IPV6_ASSOC == "false" ]]; then
			THIS_CIDR="${BLOCK}0${COUNTER}::/${PRFX_LEN_SBNT}"
			echo "Associated subnet $subnet with CIDR block $THIS_CIDR"
			aws ec2 associate-subnet-cidr-block --subnet-id $subnet \
											    --ipv6-cidr-block $THIS_CIDR \
											    --region $REGION	
			COUNTER=$[COUNTER + 1]
		fi
	done
}

create_ipv6_sg () {
	echo "Creating security group with IPv6 connectivity"
	SG_ID=$(aws ec2 create-security-group --group-name "le-log-sg-${REGION}" \
										  --description "SG for LE lookup processes."\
										  --vpc-id $VPC_ID \
										  --region $REGION | jq -r ".GroupId")
	aws ec2 wait security-group-exists \
		--filters "Name=group-id,Values=$SG_ID" \
		--region $REGION 

	aws ec2 authorize-security-group-ingress --group-id $SG_ID \
	--ip-permissions '[{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "Ipv6Ranges": [{"CidrIpv6": "::/0"}], "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]' \
	--region $REGION
}

add_ipv6_route () {
	echo "Adding IPv6 route to Internet GW routing table."
	IG_ID=$(aws ec2 describe-internet-gateways \
		    --filters "Name=attachment.vpc-id,Values=$VPC_ID" \
		    --region $REGION | jq -r ".InternetGateways[].InternetGatewayId")
	
	ROUTE_TBL_ID=$(aws ec2 describe-route-tables --region $REGION \
		           | jq -r ".RouteTables[].RouteTableId")
	
	aws ec2 create-route --route-table-id $ROUTE_TBL_ID \
						 --destination-ipv6-cidr-block ::/0 \
						 --gateway-id $IG_ID \
	                     --region $REGION
}

setup_region_ipv6 () {
	VPC_ID=$(get_default_vpc_desc | jq -r ".Vpcs[].VpcId")
	HAS_IPV6=$(get_default_vpc_desc | jq '.Vpcs[]|has("Ipv6CidrBlockAssociationSet")')
	if [[ ! $HAS_IPV6 == "true" ]] ; then
		configure_vpc_ipv6 
	fi

	configure_subnet_ipv6
	create_ipv6_sg
	add_ipv6_route
}

check_gen_key $KEY_NM

if [ "${3}" == "--setup" ]; then
	setup_region_ipv6
fi

UBUNTU_CLOUD_IMAGES="ubuntu/$PRODUCT/$RELEASE/stable/current/$ARCH/$VIRT_TYPE/$VOL_TYPE/ami-id"
UBUNTU_AMI_NAME_PATH="/aws/service/canonical/$UBUNTU_CLOUD_IMAGES"

AMI_ID=`/usr/local/bin/aws ssm get-parameters --names $UBUNTU_AMI_NAME_PATH \
--region $REGION | jq -r ".Parameters | .[] | .Value"`

aws ec2 run-instances --image-id $AMI_ID --count 1 \
	--region $REGION\
	--ipv6-address-count 1\
	--instance-type $INSTANCE_SIZE --key-name $KEY_NM \
	--security-group-ids $SG_ID --iam-instance-profile "Arn=$IAM_ARN"\
	--user-data file://instance_setup.sh

exit 0