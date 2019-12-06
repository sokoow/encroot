#!/bin/sh
###############################################################################
# This script runs the encroot script in various combinations.                #
#                                                                             #
#     Example: ./test_encroot.sh trivial example.com                          #
#                                                                             #
# Have a look at the test_suites.sh file for all details on the test suites.  #
# EC2 Regions, build platforms, target systems, processor architecture, and   #
# options are looped over to confirm that everything is working as expected.  #
# Before running, you must configure your DNS with a separate subdomain for   #
# each tested region. The domain name should point to an Elastic IP address   #
# that is available within the region. Subdomains must named be as follows:   #
#                                                                             #
#     ap-northeast-1    Tokyo                  t1.example.com                 #
#     ap-northeast-2    Seoul                  s4.example.com                 #
#     ap-south          Mumbai                 m1.example.com                 #
#     ap-southeast-1    Singapore              s1.example.com                 #
#     ap-southeast-2    Sydney                 s2.example.com                 #
#     ca-central-1      Central Canada         c2.example.com                 #
#     eu-central-1      Frankfurt              f1.example.com                 #
#     eu-west-1         Ireland                i1.example.com                 #
#     eu-west-2         London                 l1.example.com                 #
#     sa-east-1         São Paulo              s3.example.com                 #
#     us-east-1         Northern Virginia      v1.example.com                 #
#     us-east-2         Ohio                   o2.example.com                 #
#     us-west-1         Northern California    c1.example.com                 #
#     us-west-2         Oregon                 o1.example.com                 #
#                                                                             #
# Each address should be manually allocated for use in the primary test VPC,  #
# which this script will automatically create if it doesn't already exist.    #
#                                                                             #
# As an alternative, you may store "<address> <domain>" lines in a text file  #
# instead and set the environment variable ENCROOT_HOSTS to the file path.    #
# That may be easier if you don't have a quick way to update DNS records.     #
#                                                                             #
# The boot.crt and boot.key files must be stored under ../SSL/ in a directory #
# named after the subdomain of each tested region (v1, t1, etc.) and any root #
# certificate should be saved in the ../SSL/root.crt file. The latter is only #
# needed if you made your own internal Certification Authority (See SSL.txt). #
#                                                                             #
###############################################################################
#                                                                             #
# Copyright (c) 2013-2015, 2018 Henrik Gulbrandsen <henrik@gulbra.net>        #
#                                                                             #
# This software is provided 'as-is', without any express or implied warranty. #
# In no event will the authors be held liable for any damages arising from    #
# the use of this software.                                                   #
#                                                                             #
# Permission is granted to anyone to use this software for any purpose,       #
# including commercial applications, and to alter it and redistribute it      #
# freely, subject to the following restrictions:                              #
#                                                                             #
# 1. The origin of this software must not be misrepresented; you must not     #
#    claim that you wrote the original software. If you use this software     #
#    in a product, an acknowledgment in the product documentation would be    #
#    appreciated but is not required.                                         #
#                                                                             #
# 2. Altered source versions must be plainly marked as such, and must not be  #
#    misrepresented as being the original software.                           #
#                                                                             #
# 3. This notice may not be removed or altered from any source distribution,  #
#    except that more "Copyright (c)" lines may be added to already existing  #
#    "Copyright (c)" lines if you have modified the software and wish to make #
#    your changes available under the same license as the original software.  #
#                                                                             #
###############################################################################

set -e

cd "$(dirname $0)"
. ./test_suites.sh

export AWSAPI_FAILURE_COMMAND="exit 1"
export EC2_API_VERSION="2016-11-15"
PATH="$(pwd):$PATH"

### Constants #################################################################

# Files copied to the build system
BUILD_FILES="activate.cgi awsapi boot.crt boot.key cryptsetup cryptsetup.sh
    hiding.gif index.html init.sh make_bozo_dir.sh make_encrypted_distro.sh
    pre_init.sh encroot uecimage.gpg"

# Output format and file
FORMAT="%-16s %-10s %-10s %-7s %-12s %-12s %s\n"
LOG_FILE="test_results.txt"

# Address ranges, security group and SSH keys
CIDR_VPC="10.20.0.0/16"
CIDR_NET="10.20.1.0/24"
GROUP="Encroot Test"
KEY_NAME="TEST_key1"
KEY_FILE="$HOME/.ssh/$KEY_NAME"

# Random passwords for the encryption test
PASSWORD1="aae856476490bf1466bcc8fecf38c1ac"
PASSWORD2="4951649e0063075ecbc75306a5f2783c"

# Let's hope this doesn't change...
UBUNTU_AWS_ACCOUNT="099720109477"

### Global Variables ##########################################################

base_domain=""
buildInstance_instanceId=""
buildInstance_ipAddress=""
current_groupId=""
current_platform=""
current_region=""
current_subnetId=""
suite_name=""
test_count=0
test_index=0

### Parameters ################################################################

print_test_count() {
    local list count=1

    for list in REGIONS PLATFORMS TARGETS ARCHS TYPES OPTIONS; do
        eval set -- \$$list; count=$((count*$#));
    done

    echo $count;
}

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
    echo "Usage: ${0##*/} [<suite>] <base-domain>"
    echo
    echo "Suites:"
    for suite in $SUITES; do
        DESCRIPTION="No description"
        SUITE_${suite}; count="$(print_test_count)"
        printf "    %-8s %-40s  %3d test" "$suite:" "$DESCRIPTION" $count
        if [ $count -eq 1 ]; then echo ""; else echo "s"; fi
    done
    echo
    exit 1
fi

### Validation ################################################################

if [ $# -eq 1 ]; then
    suite_name="default"
    base_domain="$1"
else
    suite_name="$1"
    base_domain="$2"
fi

if [ "${base_domain}" = "example.com" ] ||
   [ "${base_domain%.example.com}" != "${base_domain}" ]; then
    echo "No, dummy! You should use your own domain, not example.com!"
    exit 1
fi

if [ -z "${suite_name}" ]; then
    echo "Error: Blank suite"
    exit 1
fi

if [ -z "${base_domain}" ]; then
    echo "Error: Blank domain"
    exit 1
fi

if ! type "SUITE_${suite_name}" 2> /dev/null | grep -q "function"; then
    echo "Invalid suite: ${suite_name}"
    exit 1
fi

SUITE_${suite_name};

### Functions #################################################################

dots() {
    perl -e 'print $ARGV[0], "."x(45-length($ARGV[0])), "... "' "$*";
}

print_separator() {
    printf "%s" "----------------------------------------"
    echo "---------------------------------------"
}

log() {
    printf "$@" >> "$LOG_FILE";
}

need() {
    if [ ! -e "$1" ]; then
        echo "Missing file: $1 - $2"
        exit 1
    fi
}

print_domain_for_region() {
    local region=$1
    local domain

    case $region in
        ap-northeast-1) domain="t1.$base_domain" ;; # Tokyo
        ap-northeast-2) domain="s4.$base_domain" ;; # Seoul
        ap-south-1)     domain="m1.$base_domain" ;; # Mumbai
        ap-southeast-1) domain="s1.$base_domain" ;; # Singapore
        ap-southeast-2) domain="s2.$base_domain" ;; # Sydney
        ca-central-1)   domain="c2.$base_domain" ;; # Central Canada
        eu-central-1)   domain="f1.$base_domain" ;; # Frankfurt
        eu-west-1)      domain="i1.$base_domain" ;; # Ireland
        eu-west-2)      domain="l1.$base_domain" ;; # London
        sa-east-1)      domain="s3.$base_domain" ;; # São Paulo
        us-east-1)      domain="v1.$base_domain" ;; # Northern Virginia
        us-east-2)      domain="o2.$base_domain" ;; # Ohio
        us-west-1)      domain="c1.$base_domain" ;; # Northern California
        us-west-2)      domain="o1.$base_domain" ;; # Oregon
    esac

    echo "$domain"
}

print_address_for_domain() {
    local address=""

    # Try the Encroot hosts file first
    if [ -n "$ENCROOT_HOSTS" ] && [ -f "$ENCROOT_HOSTS" ]; then
        address=$(perl -ne 'print $1 if m[^(\S+)\s+'$1']' "$ENCROOT_HOSTS")
    fi

    # Fall back to DNS if it wasn't found
    if [ -z "$address" ]; then
        address=$(dig +short "$1")
    fi

    echo "$address"
}

print_instance_name() {
    local option="$1" target="$2" arch="$3"
    local name

    case $option in
      --big-boot) name="TEST_BigBoot";;
      *) name="TEST_Normal";;
    esac

    name="$name$(echo $target | perl -pe 's/(.*)/\u$1/')"

    case $arch in
      i386) name="${name}32";;
      x86_64) name="${name}64";;
    esac

    echo "$name"
}

confirm_ssh() {
    local address="$1"
    local known attempt

    # Make sure that the address won't make SSH nervous
    known="$HOME/.ssh/known_hosts"
    grep -v "^$address " "${known}" 2> /dev/null > "${known}.new"
    mv "${known}.new" "${known}"

    # Wait for the SSH daemon to start
    for attempt in 0 1 2 3 4 5 6 7 8 9; do sleep 10
        ssh -i "$KEY_FILE" -o StrictHostKeyChecking=no "admin@$address" true \
            2>/dev/null && break || true # Ignore errors; break on success
        ssh -i "$KEY_FILE" -o StrictHostKeyChecking=no "ubuntu@$address" true \
            2>/dev/null && break || true # Ignore errors; break on success
        if [ $attempt = 9 ]; then
            return 1
        fi
    done

    return 0
}

activate_server() {
    local domain="$1"
    local curlOptions
    local address
    local attempt

    curlOptions="--data key=$PASSWORD1"
    if [ -e "../SSL/root.crt" ]; then
        curlOptions="$curlOptions --cacert ../SSL/root.crt";
    fi

    if [ -n "$ENCROOT_HOSTS" ] && [ -f "$ENCROOT_HOSTS" ]; then
        address="$(print_address_for_domain $domain)"
        curlOptions="$curlOptions --resolve $domain:443:$address"
    fi

    curlOptions="$curlOptions --silent --show-error"
    curlOptions="$curlOptions --output /dev/null"
    curlOptions="$curlOptions --connect-timeout 5"
    curlOptions="$curlOptions --retry 12"

    # An explicit loop since curl won't retry after "Connection refused"
    for attempt in 0 1 2 3 4; do sleep 10
        curl $curlOptions "https://$domain/cgi-bin/activate.cgi" \
            2>/dev/null && break || true
        if [ $attempt = 1 ]; then
            return 1
        fi
    done

    return 0;
}

terminate_domain() {
    local domain="$1"
    local ipAddress instance instanceList

    # Find the IP address of the domain
    ipAddress="$(print_address_for_domain "$domain")"
    if [ -z "$ipAddress" ]; then
        echo "No IP address for $domain"
        exit 1
    fi

    # Find test instances with the given IP address
    $(awsapi ec2.DescribeInstances instance+reservationSet.n.instancesSet.1.{ \
        instanceId, keyName eq "$KEY_NAME", \
        group:groupSet.1.groupName eq "$GROUP", \
        state:instanceState.name ne terminated, \
        ipAddress eq "$ipAddress" \
    })

    # We only expect one instance to match, but...
    for instance in $instanceList; do

        # Confirm the address, just in case our awsapi filter is buggy
        if [ "$(instance.ipAddress)" != "$ipAddress" ]; then
            echo "Bad IP address: \"$(instance.ipAddress)\" != \"$ipAddress\""
            exit 1
        fi

        # Confirm the key, in case the bug is somewhere else
        if [ "$(instance.keyName)" != "$KEY_NAME" ]; then
            echo "Wrong key: $(instance.keyName)";
            exit 1
        fi

        # Check the group too, just to be sure
        if [ "$(instance.group)" != "$GROUP" ]; then
            echo "Wrong group: $(instance.group)";
            exit 1
        fi

        # If everything looks OK, terminate the instance
        $(awsapi ec2.TerminateInstances \
            InstanceId.1="$(instance.instanceId)")

    done
}

prepare_region() {
    local region="$1"
    local query

    # Set the endpoint for the new region
    export EC2_ENDPOINT="https://ec2.$region.amazonaws.com/"

    # Create and import a separate key pair if needed
    query="awsapi ec2.DescribeKeyPairs KeyName.1"
    if $query="$KEY_NAME" 2>&1 | grep -q InvalidKeyPair.NotFound; then
        dots "Importing key pair"
        if [ ! -e "$KEY_FILE" ]; then
            mkdir -p "$(dirname "$KEY_FILE")"
            ssh-keygen -q -t rsa -b 2048 -N "" -C "$KEY_NAME" -f "$KEY_FILE"
        fi
        $(awsapi ec2.ImportKeyPair KeyName="$KEY_NAME" PublicKeyMaterial="$(
            cat "$KEY_FILE".pub | openssl base64 | tr -d '\n')")
        echo "done"
    fi

    # Confirm that we have the private key
    if [ ! -e "$KEY_FILE" ]; then
        echo "Missing key: $KEY_FILE"
        exit 1
    fi

    # Prepare the test VPC
    prepare_vpc;
}

prepare_vpc() {
    local vpcId

    # Check if we have a suitable VPC
    $(awsapi ec2.DescribeVpcs Filter.1.{ Name=cidr, Value.1="$CIDR_VPC" } \
        vpcSet.1.vpcId or "missing")

    # Create the VPC if necessary
    if [ "$vpcId" = "missing" ]; then
        dots "Creating test VPC..."
        $(awsapi ec2.CreateVpc CidrBlock="$CIDR_VPC" vpc.vpcId)
        echo "$vpcId"
    fi

    # Configure the VPC if necessary
    prepare_internet_gateway $vpcId
    prepare_subnet $vpcId
    prepare_group $vpcId
}

prepare_internet_gateway() {
    local vpcId="$1" internetGatewayId originalGatewayId

    # Check if we have a suitable Internet gateway
    $(awsapi ec2.DescribeInternetGateways \
        Filter.1.{ Name=attachment.vpc-id, Value.1="$vpcId" } \
        internetGatewaySet.1.internetGatewayId or "missing")

    # Remember what we used to have
    originalGatewayId="$internetGatewayId"

    # If no gateway was attached to the VPC:
    if [ "$internetGatewayId" = "missing" ]; then

        # Look for a gateway with no VPC attached
        $(awsapi ec2.DescribeInternetGateways \
            gateway+internetGatewaySet.n.{ \
                attachmentSet.1.vpcId eq "", \
                id:internetGatewayId \
            } \
         )

         # Use the first such gateway found
         for gateway in $gatewayList; do
             internetGatewayId=$(gateway.id)
             break
         done

    fi

    # Create the Internet gateway if necessary
    if [ "$internetGatewayId" = "missing" ]; then
        dots "Creating Internet gateway..."
        $(awsapi ec2.CreateInternetGateway internetGateway.internetGatewayId)
        echo "$internetGatewayId"
    fi

    # Attach the Internet gateway if necessary
    if [ "$originalGatewayId" = "missing" ]; then
        dots "Attaching Internet gateway..."
        $(awsapi ec2.AttachInternetGateway VpcId=$vpcId \
            InternetGatewayId=$internetGatewayId)
        echo "done"
    fi

    # Prepare the default route
    prepare_route_table $vpcId $internetGatewayId
}

prepare_route_table() {
    local vpcId="$1" internetGatewayId="$2"
    local routeTableId configuredRouteTableId

    # Check if the VPC has a route table
    $(awsapi ec2.DescribeRouteTables \
        Filter.1.{ Name=vpc-id, Value.1="$vpcId" } \
        routeTableSet.1.routeTableId or "missing")

    # Create the route table if necessary
    if [ "$routeTableId" = "missing" ]; then
        dots "Creating route table..."
        $(awsapi ec2.CreateRouteTable VpcId=$vpcId routeTable.routeTableId)
        echo "$routeTableId"
    fi

    # Check if the VPC has a default route
    $(awsapi ec2.DescribeRouteTables \
        Filter.1.{ Name=vpc-id, Value.1="$vpcId" } \
        Filter.2.{ Name=route.destination-cidr-block, Value.1="0.0.0.0/0" } \
        configuredRouteTableId:routeTableSet.1.routeTableId or "missing")

    # Create the default route if necessary
    if [ "$configuredRouteTableId" = "missing" ]; then
        dots "Creating default route..."
        $(awsapi ec2.CreateRoute RouteTableId=$routeTableId \
            DestinationCidrBlock="0.0.0.0/0" \
            GatewayId=$internetGatewayId)
        echo "done"
    fi
}

prepare_subnet() {
    local vpcId="$1"

    # Check if we have a suitable subnet
    $(awsapi ec2.DescribeSubnets \
        Filter.1.{Name=vpc-id, Value.1="$vpcId"} \
        Filter.2.{Name=cidr, Value.1="$CIDR_NET"} \
        current_subnetId:subnetSet.1.subnetId or "missing")

    # Create the subnet if necessary
    if [ "$current_subnetId" = "missing" ]; then
        dots "Creating test subnet..."
        $(awsapi ec2.CreateSubnet VpcId="$vpcId" CidrBlock="$CIDR_NET" \
            current_subnetId:subnet.subnetId)
        echo "$current_subnetId"
    fi
}

prepare_group() {
    local vpcId="$1"

    # Look for the matching security group
    $(awsapi ec2.DescribeSecurityGroups \
        Filter.1.{Name=vpc-id, Value="$vpcId"} \
        Filter.2.{Name=group-name, Value="$GROUP"} \
        current_groupId:securityGroupInfo.1.groupId or "missing")

    # Is the security group missing?
    if [ "$current_groupId" = "missing" ]; then
        dots "Creating security group..."

        # Then create a new security group...
        $(awsapi ec2.CreateSecurityGroup VpcId="$vpcId" GroupName="$GROUP" \
            GroupDescription="Used by ${0##*/}" current_groupId:groupId)

        # ...and add SSH and HTTPS ingress rules
        $(awsapi ec2.AuthorizeSecurityGroupIngress \
            GroupId="$current_groupId" \
            IpPermissions.1.{ \
                IpProtocol=tcp, \
                FromPort=22, ToPort=22, \
                IpRanges.1.CidrIp="0.0.0.0/0" \
            } \
            IpPermissions.2.{ \
                IpProtocol=tcp, \
                FromPort=443, ToPort=443, \
                IpRanges.1.CidrIp="0.0.0.0/0" \
            } \
        )

        echo "$current_groupId"
    fi
}

prepare_build_system() {
    local region="$1" platform="$2"

    # Kill the old instance
    if [ -n "$buildInstance_instanceId" ]; then
        $(awsapi ec2.TerminateInstances \
            InstanceId.1="$buildInstance_instanceId")
    fi

    # Prepare the region environment
    if [ "$region" != "$current_region" ]; then
        prepare_region "$region"
        current_region="$region"
    fi

    # Create a new instance
    prepare_build_instance "$region" "$platform" "x86_64"
}

prepare_build_instance() {
    local region="$1" platform="$2" arch="$3"
    local pattern="ubuntu/images/hvm*/ubuntu-$platform-*"
    local object objectList
    local imageId bits domain

    # Find a suitable AMI for this region, platform, and architecture
    dots "Selecting image"
    imageId=$($(awsapi --table ec2.DescribeImages Owner.1=$UBUNTU_AWS_ACCOUNT \
        Filter.1.Name=architecture Filter.1.Value.1=$arch \
        Filter.2.Name=root-device-type Filter.2.Value.1=ebs \
        Filter.3.Name=virtualization-type Filter.3.Value.1=hvm \
        Filter.4.Name=name Filter.4.Value.1="$pattern" \
        object+imagesSet.n.{name,imageId}) | \
        sort | tail -1 | awk '{print $2}')
        echo "$imageId"

    # Complain if it doesn't look like an image ID
    if [ "${imageId}" = "${imageId#ami-}" ]; then
        echo "Weird AMI: \"$imageId\""
        exit 1
    fi

    # Start the instance and install necessary files
    start_build_instance "$imageId" "$platform" "$arch"
    print_separator; install_files "$region"
}

start_build_instance() {
    local imageId="$1" platform="$2" arch="$3"
    local instanceId bits state ipAddress

    # Start the new build instance
    dots "Starting instance"
    $(awsapi ec2.RunInstances ImageId="$imageId" MinCount=1 MaxCount=1 \
        NetworkInterface.0.{ \
            DeviceIndex="0", SubnetId="$current_subnetId", \
            SecurityGroupId.1="$current_groupId", \
            AssociatePublicIpAddress=true \
        } \
        KeyName="$KEY_NAME" InstanceType=t2.micro \
        instancesSet.1.instanceId)
        sleep 5; echo "$instanceId"

    # Give it a name like "TEST_Precise64_Build"
    dots "Naming instance"
    if [ "$arch" = i386 ]; then bits=32; else bits=64; fi
    name="$name$(echo $platform | perl -pe 's/(.*)/\u$1/')"
    $(awsapi ec2.CreateTags ResourceId.1="$instanceId" \
        Tag.1.{ Key=Name, Value="TEST_${name}${bits}_Build" })
        echo "TEST_${name}${bits}_Build"

    # Wait for the new instance to start
    dots "Waiting for instance"
    $(awsapi ec2.DescribeInstances \
        Filter.1.{ Name="instance-id", Value.1="$instanceId" } \
        reservationSet.1.instancesSet.1.{ \
            state:instanceState.name := -/pending/running, \
            ipAddress \
        }); echo "done"

    # Wait for the SSH daemon to start
    dots "Waiting for SSH daemon"
    if ! confirm_ssh $ipAddress; then
        echo "Could not reach $ipAddress"
        exit 1
    fi

    # Wait and repeat, since SSH host keys may change
    sleep 10; if ! confirm_ssh $ipAddress; then
        echo "Lost connection to $ipAddress"
        exit 1
    fi

    # Save the necessary details
    buildInstance_instanceId="$instanceId"
    buildInstance_ipAddress="$ipAddress"
    echo "done";
}

install_files() {
    local region="$1"
    local ipAddress="$buildInstance_ipAddress"
    local domain sslDir ttyState

    # Select certificates for the domain
    domain=$(print_domain_for_region "$region")
    sslDir="../SSL/${domain%.$base_domain}"
    cp "$sslDir/boot.crt" "$sslDir/boot.key" .

    # Make the next step look nicer
    ttyState=$(stty -g)
    stty cols 80

    # Copy all necessary files
    ssh -i "$KEY_FILE" "ubuntu@$ipAddress" mkdir encroot
    scp -i "$KEY_FILE" $BUILD_FILES "ubuntu@$ipAddress:encroot"
    scp -i "$KEY_FILE" "$HOME"/.awsapirc "ubuntu@$ipAddress:/home/ubuntu"
    stty "$ttyState"
    print_separator;

    # Workaround for an annoying sudo warning on some distros
    # (sudo: unable to resolve host ip-10-20-1-181)
    ssh -i "$KEY_FILE" "ubuntu@$ipAddress" sudo 2> /dev/null \
        '/bin/sh -c "echo $(hostname -I) $(hostname) >> /etc/hosts"'

    # Install cryptsetup
    ssh -ti "$KEY_FILE" "ubuntu@$ipAddress" sudo \
        apt-get -y install cryptsetup
    print_separator;

    # These should not be packaged...
    rm -f boot.crt boot.key
}

print_test_header() {
    local region="$1" platform="$2" target="$3"
    local arch="$4" type="$5" option="$6"

    print_separator;
    printf "%40s %d/%d\n" "TEST" "$test_index" "$test_count"
    print_separator;
    echo "Region.......... $region"
    echo "Platform........ $platform"
    echo "Target.......... $target"
    echo "Architecture.... $arch"
    echo "Instance type... $type"
    echo "Options......... $option"
    print_separator;
}

is_skipped_combination() {
    local region="$1" platform="$2" target="$3"
    local arch="$4" type="$5" option="${6#none}"

    # Strip the distro prefix
    target="${target#debian-}"
    target="${target#ubuntu-}"

    # Debian 6 (Squeeze) only has paravirtual builds
    if [ "$target" = "squeeze" ] && [ "$type" = "t2.micro" ]; then
        return 0
    fi

    # Debian 7 (Wheezy) only has paravirtual builds for i386
    if [ "$target" = "wheezy" ] && [ "$arch" = "i386" ] \
    && [ "$type" = "t2.micro" ]; then
        return 0
    fi

    # Debian 8 (Jessie) only has 64-bit builds
    if [ "$target" = "jessie" ] && [ "$arch" = "i386" ]; then
        return 0
    fi

    # Debian 9 (Stretch) only has 64-bit builds
    if [ "$target" = "stretch" ] && [ "$arch" = "i386" ]; then
        return 0;
    fi

    # Debian 9 (Stretch) only has HVM builds
    if [ "$target" = "stretch" ] && [ "$type" = "t1.micro" ]; then
        return 0;
    fi

    # The Frankfurt region doesn't support "t1.micro" instances
    if [ "$region" = "eu-central-1" ] && [ "$type" = "t1.micro" ]; then
        return 0
    fi

    # 32-bit Ubuntu 17.10 (Artful) with Linux 4.13 seems to get stuck in a
    # boot loop for HVM instances on Xeon E5-2670 v2 @ 2.50GHz, although it
    # works on Xeon E5-2676 v3 @ 2.40GHz. The hardware selection is random,
    # so we'll skip this combination for now. Feel free to restore it later.
    if [ "$target" = "artful" ] && [ "$arch" = "i386" ] \
    && [ "$type" = "t2.micro" ]; then
        return 0;
    fi

    return 1
}

test_combination() {
    local region="$1" platform="$2" target="$3"
    local arch="$4" type="$5" option="${6#none}"
    local domain address name args

    print_test_header "$@"

    # Prepare everything for the main encroot script
    if [ "${region}_${platform}" != "$current_platform" ]; then
        prepare_build_system "$region" "$platform";
        current_platform="${region}_${platform}"
    fi

    # Prepare script arguments
    domain=$(print_domain_for_region "$region")
    address=$(print_address_for_domain "$domain")
    name=$(print_instance_name "$option" "$target" "$arch")
    option="${option:+ $option}"

    # Adjust target for 32/64-bit
    case $arch in
      i386) target="${target}/i386";;
      x86_64) target="${target}/amd64";;
    esac

    # Run the encroot scripts
    args="--name='$name' --system='$target' --type='$type' --group='$GROUP'"
    printf "$PASSWORD1\n$PASSWORD1\n$PASSWORD2\n$PASSWORD2\n\n" | \
      ssh -tt -i "$KEY_FILE" "ubuntu@$buildInstance_ipAddress" \
        "cd encroot && ./encroot$option $args $address" \
            || return 1

    # Activate the new server
    dots "Activating server"
    if ! activate_server "$domain"; then
        echo "failed"; terminate_domain "$domain"; return 1;
    else
        echo "done"
    fi

    # Verify that it comes up
    dots "Confirming SSH"
    if ! confirm_ssh "$address"; then
        echo "failed"; terminate_domain "$domain"; return 1;
    else
        echo "done"
    fi

    # Terminate the server
    terminate_domain "$domain"
    return 0;
}

### Sanity Check ##############################################################

for region in $REGIONS; do

    # Verify the DNS configuration
    domain=$(print_domain_for_region "$region")
    if [ -z $(print_address_for_domain "$domain") ]; then
        echo "Missing domain for $region: $domain"
        exit 1
    fi

    # Confirm that we have necessary files
    dir="../SSL/${domain%.$base_domain}"
    need "$dir/boot.crt" "SSL certificate for $domain"
    need "$dir/boot.key" "private SSL key for $domain"

done

### Run the tests #############################################################

combinations=""

# Make a list of all combinations
for region in $REGIONS; do
  for platform in $PLATFORMS; do
    for target in $TARGETS; do
      for arch in $ARCHS; do
        for type in $TYPES; do
          for option in $OPTIONS; do
            combination="$region:$platform:$target:$arch:$type:$option"
            combinations="$combinations $combination"
            test_count=$((test_count+1))
          done
        done
      done
    done
  done
done

# Print the result header
:> $LOG_FILE # ...starting with an empty file
log "$FORMAT" "Region" "Platform" "Target" "Arch" "Type" "Option" "Result"
log "%s\n" "$(print_separator)"

# Test all combinations
for combination in $combinations; do
    test_index=$((test_index+1))
    combination=$(echo $combination | sed 's/:/ /g')
    if is_skipped_combination $combination; then result="-";
    elif test_combination $combination; then result="OK";
    else result="Bad"; fi
    combination=$(echo $combination | sed 's/debian-//g')
    log "$FORMAT" $combination $result
done

# Terminate the remaining build instance
if [ -n "$buildInstance_instanceId" ]; then
    $(awsapi ec2.TerminateInstances InstanceId.1="$buildInstance_instanceId")
fi

###############################################################################
