#!/bin/sh
###############################################################################
# This file contains alternative suites run by the test_encroot.sh script.    #
#                                                                             #
# It's included as is at the beginning of test_encroot.sh, but is a separate  #
# file to encourage users to add simple modifications and extra suites. This  #
# code is trivial, so I consider it to be in the public domain.               #
#                                                                             #
###############################################################################

SUITES="32_bits bigboot default distros failure
        regions release trivial"

SUITE_32_bits() {
    DESCRIPTION="32-bit test for each supported distro"
    REGIONS="us-east-1"
    PLATFORMS="xenial"
    TARGETS="trusty xenial artful wheezy jessie stretch"
    ARCHS="i386"
    TYPES="t1.micro t2.micro"
    OPTIONS="none"
}

SUITE_bigboot() {
    DESCRIPTION="Test with --big-boot on all distros"
    REGIONS="us-east-1"
    PLATFORMS="xenial"
    TARGETS="trusty xenial artful wheezy jessie stretch"
    ARCHS="x86_64"
    TYPES="t1.micro t2.micro"
    OPTIONS="--big-boot"
}

SUITE_default() {
    DESCRIPTION="64-bit Ubuntu + Debian (normal/big-boot)"
    REGIONS="us-east-1"
    PLATFORMS="xenial"
    TARGETS="ubuntu debian"
    ARCHS="x86_64"
    TYPES="t2.micro"
    OPTIONS="none --big-boot"
}

SUITE_distros() {
    DESCRIPTION="64-bit test for each supported distro"
    REGIONS="us-east-1"
    PLATFORMS="xenial"
    TARGETS="trusty xenial artful wheezy jessie stretch"
    ARCHS="x86_64"
    TYPES="t1.micro t2.micro"
    OPTIONS="none"
}

SUITE_failure() {
    DESCRIPTION="A failure to care about"
    REGIONS="us-east-1"
    PLATFORMS="xenial"
    TARGETS="jessie"
    ARCHS="i386"
    TYPES="t2.micro"
    OPTIONS="none"
}

SUITE_regions() {
    DESCRIPTION="64-bit test for each available region"
    REGIONS="ap-northeast-1  ap-northeast-2  ap-south-1
             ap-southeast-1  ap-southeast-2  ca-central-1
             eu-central-1    eu-west-1       eu-west-2
             sa-east-1       us-east-1       us-east-2
             us-west-1       us-west-2"
    PLATFORMS="xenial"
    TARGETS="xenial"
    ARCHS="x86_64"
    TYPES="t2.micro"
    OPTIONS="none"
}

SUITE_release() {
    DESCRIPTION="The official Encroot release suite"
    REGIONS="us-east-1 ap-northeast-1 eu-central-1"
    PLATFORMS="xenial"
    TARGETS="trusty xenial artful wheezy jessie stretch"
    ARCHS="i386 x86_64"
    TYPES="t1.micro t2.micro"
    OPTIONS="none --big-boot"
}

SUITE_trivial() {
    DESCRIPTION="Tests only 64-bit Xenial Xerus"
    REGIONS="us-east-1"
    PLATFORMS="xenial"
    TARGETS="xenial"
    ARCHS="x86_64"
    TYPES="t2.micro"
    OPTIONS="none"
}

###############################################################################
