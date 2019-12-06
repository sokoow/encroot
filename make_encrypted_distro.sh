#!/bin/sh
###############################################################################
# This script is used to build an encrypted EBS-backed system for Amazon EC2. #
#                                                                             #
# Tested with ami-41e0b93b (64-bit EBS us-east-1 - Ubuntu 16.04 LTS)          #
# See https://help.ubuntu.com/community/UEC/Images for info on Ubuntu images. #
# Xenial Xerus: https://cloud-images.ubuntu.com/releases/xenial/release/      #
#                                                                             #
###############################################################################
#                                                                             #
# Copyright (c) 2011, 2013-2015, 2018 Henrik Gulbrandsen <henrik@gulbra.net>  #
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

exitValue=1
set -e

### Parameters and validation #################################################

big_boot=false
no_color=false
no_fonts=false
no_lines=false
no_style=false
trust_me=false
validate=false
bootsize="default"
fix_hook=""
if_count=1

my_agent=$(curl --version | head -1 | awk '{print $1 "/" $2}')
web_port=443

while [ "_${1#-}" != "_$1" ]; do
    case $1 in
        --big-boot) big_boot=true; shift;;
        --no-color) no_color=true; shift;;
        --no-fonts) no_fonts=true; shift;;
        --no-lines) no_lines=true; shift;;
        --no-style) no_style=true; shift;;
        --trust-me) trust_me=true; shift;;
        --validate) validate=true; shift;;

        --bootsize) bootsize="$2"; shift 2;;
        --bootsize=*) bootsize="${1#--bootsize=}"; shift;;

        --fix-hook) fix_hook="$2"; shift 2;;
        --fix-hook=*) fix_hook="${1#--fix-hook=}"; shift;;

        --if-count) if_count="$2"; shift 2;;
        --if-count=*) if_count="${1#--if-count=}"; shift;;

        --my-agent) my_agent="$2"; shift 2;;
        --my-agent=*) my_agent="${1#--my-agent=}"; shift;;

        --web-port) web_port="$2"; shift 2;;
        --web-port=*) web_port="${1#--web-port=}"; shift;;

        *) break;;
    esac
done

if $validate; then
    dev=/dev/sdf
    host=www.example.org
    system=$3
else
    dev=$1
    host=$2
    system=$3
fi

# Check if "system" is a directory
if [ ! -d "$system" ]; then
    unset systemDir
else
    systemDir="$system"
    unset system
fi

if [ "${dev#/dev/}" = "${dev}" -o -z "$host" ]; then
    echo "Usage: ${0##*/} [<options>] <device> <domain> [<system>]"
    echo "    --big-boot: full system on /dev/sda1, not just /boot"
    echo "    --bootsize: size of boot partition in 512-byte blocks"
    echo "    --fix-hook: hook script to fix distro-specific things"
    echo "    --if-count: total number of ethX network interfaces"
    echo "    --my-agent: text used for the \"User-Agent\" HTTP header"
    echo "    --no-color: remove all annoying colors from the output"
    echo "    --no-fonts: remove bold and thin fonts from the output"
    echo "    --no-lines: replace underscore lines with ASCII dashes"
    echo "    --no-style: remove VT100 escape codes from the output"
    echo "    --trust-me: skip the confirmation for device erasing"
    echo "    --validate: run a few initial sanity checks and exit"
    echo "    --web-port: alternative port number for the web server"
    echo "        device: the device where a blank EBS is attached"
    echo "        domain: DNS domain for decryption password entry"
    echo "        system: e.g. \"lucid-20101228\" or \"maverick/i386\""
    exit 1
fi

# Keep an absolute script path for later
fix_hook=$(readlink -f "$fix_hook" || true)

if [ "$bootsize" = "default" ]; then
    if $big_boot; then bootsize="4194304"; else bootsize="2097152"; fi
fi

if [ "$bootsize" -le 0 ] 2> /dev/null; then
    echo "The boot size must be a positive integer."
    exit 1
fi

if [ -n "$fix_hook" ] && ! [ -f "$fix_hook" -a -x "$fix_hook" ]; then
    echo "The fix hook must be an executable file."
    exit 1
fi

if ! [ "$if_count" -ge 1 -a "$if_count" -le 8 ] 2> /dev/null; then
    echo "The range is from --if-count=1 to --if-count=8"
    exit 1
fi

if [ "${host%.example.com}" != "${host}" -o -z "${host%example.com}" ]; then
    echo "No, dummy! You should use your own domain, not example.com!"
    exit 1
fi

if [ "${system#snap-}" != "$system" ]; then
    echo "Snapshot-based systems are still not supported."
    exit 1
fi

if [ "$(id -u)" != "0" ]; then
    echo "This script should be run as root."
    exit 1
fi

require() {
    local package="${1##*/}"
    local path="$1"

    if [ ! -e "${path}" ]; then
        echo "Please install ${package} (using this command):"
        echo "    sudo apt-get -y install ${package}"; echo
        exit 1
    fi
}

require /sbin/cryptsetup

### Colors & Separators (duplicated code) #####################################

BOLD="1" # Bright text
THIN="2" # Dimmed text
LINE="4" # Underscores

NORMAL="39;0"
BOLD_RED="31;1"
BOLD_GREEN="32;1"
BOLD_YELLOW="33;1"
BOLD_BLUE="34;1"
BOLD_MAGENTA="35;1"
BOLD_CYAN="36;1"

fancyTerminal=false

# Check if the current terminal can handle color
if [ -n "${TERM}" ]; then
    for term in $(dircolors -p | grep "^TERM" | awk '{print $2}'); do
        if [ -z "${TERM#$term}" ]; then fancyTerminal=true; break; fi
    done
fi

# Use fancy output if it looks like the terminal can handle it
if ! $no_style && [ -t 1 ] && $fancyTerminal; then
    fancy=true
else
    fancy=false
fi

# Fancy output comes with a nice underline separator
if $fancy && ! $no_lines; then
    separator="$(printf '\033[4m%79s\033[0m' '')"
else
    separator="$(printf '%79s' '' | tr ' ' '-')"
fi

print_separator() {
    printf "%s\n\n" "$separator"
}

set_display_mode() {
    local mode="$1"

    case $mode in
        $BOLD) if $no_fonts; then return; fi;;
        $THIN) if $no_fonts; then return; fi;;
        $LINE) if $no_lines; then return; fi;;
        $NORMAL) ;;
        *) if $no_color; then return; fi
           if $no_fonts; then mode="${mode%;1}"; fi
    esac

    if $fancy; then command printf "\033[${mode}m"; fi
}

print_header() {
    echo; print_separator;
    perl -e 'print " "x(40-length($ARGV[0])/2)' "$1";
    set_display_mode "$BOLD"
    set_display_mode "$LINE"
    printf "$1\n\n"
    set_display_mode "$NORMAL"
    echo
}

### Unique VT100 code #########################################################

hide_cursor() {
    if $fancy; then printf "\033[?25l"; fi
}

show_cursor() {
    if $fancy; then printf "\033[?25h"; fi
}

tick() {
    set_display_mode "$BOLD_GREEN"
    echo "$@"
    set_display_mode "$NORMAL"
}

warn() {
    set_display_mode "$BOLD_RED"
    echo "$@"
    set_display_mode "$NORMAL"
}

bold_printf() {
    set_display_mode "$BOLD"
    printf "$@"
    set_display_mode "$NORMAL"
}

run_block() {
    print_header "$1"

    # For each command line:
    while read line; do

        # Display a bold prompt...
        set_display_mode "$BOLD"
        printf "Encroot#"

        # ...and a normal command...
        set_display_mode "$NORMAL"
        printf " %s\n" "$line"

        # ...followed by dimmed output
        set_display_mode "$THIN"
        chroot "${work}/root" /bin/sh -c "$line"

    done
}

### Sanity checks #############################################################

# Confirm that the port number is reasonable
if [ "$web_port" -ge 1 ] && [ "$web_port" -le 65535 ] 2> /dev/null; then
    port="$web_port"
else
    echo "Invalid port number: $web_port"
    exit 1
fi

# Find the application and certificate directories
home="$(dirname $(readlink -f $0))"
cert="$(pwd)"

old=$([ "${system#snap-}" != "$system" ] && echo "true" || echo "false")
new=$( ($old || $big_boot) && echo "true" || echo "false")
ram=$($big_boot && echo "false" || echo "true")
big=$big_boot
ram_boot=$ram

if [ "$(which cryptsetup)" = "${home}/cryptsetup" ]; then
    echo "Bad PATH: ${home}/cryptsetup hides /sbin/cryptsetup"
    echo "Please update your PATH environment variable."
    exit 1
fi

need() {
    local needed="$1"; shift
    local mode="$1"; shift
    local folder="$1"; shift
    local name="$1"; shift
    local text="$1"; shift

    if ! $needed; then return; fi

    if [ ! -e "$folder/$name" ]; then
        echo "Missing file: $name - $text"
        exit 1
    else
        # Files moved via Windows may have lost permissions...
        chmod $mode "$folder/$name"
    fi
}

need true 600 "$cert" "boot.key" "private SSL key for the boot partition"
need true 644 "$cert" "boot.crt" "SSL certificate for the boot partition"
need $big 755 "$home" "init.sh" "boot script replacing /sbin/init"
need $big 644 "$home" "pre_init.sh" "boot script that gets the password"
need $ram 755 "$home" "cryptsetup" "initramfs hook script"
need $ram 755 "$home" "cryptsetup.sh" "initramfs cryptsetup replacement"
need true 755 "$home" "make_bozo_dir.sh" "bozohttpd home setup script"
need true 644 "$home" "index.html" "page that redirects to activate.cgi"
need true 755 "$home" "activate.cgi" "password-fetching CGI script"
need true 644 "$home" "hiding.gif" "animated GIF used to hide text"
need $new 644 "$home" "uecimage.gpg" "public key for Ubuntu images"

### Decryption of private key #################################################

# At least one user has been confused by this mistake
if grep -q "[ ,]ENCRYPTED" "${cert}/boot.key"; then
    echo "Your \"boot.key\" file is encrypted; that won't work!"

    # Keys are important; avoid overwriting them below
    if [ -e boot.key.decrypted ] || [ -e boot.key.encrypted ]; then
        echo "Please decrypt it before running the script."
        exit 1
    fi

    # Give the user a chance to decrypt the key
    mask=$(umask); umask 077
    openssl rsa -in boot.key -out boot.key.decrypted 2> /dev/null
    umask $mask

    # Use the decrypted key instead of the old one
    chown --reference=boot.key boot.key.decrypted
    mv boot.key boot.key.encrypted
    mv boot.key.decrypted boot.key
    echo
fi

### Select a system version ###################################################

ARCH="unknown"

# Select a reasonable default architecture
file /bin/ls | grep -q 32-bit && ARCH="i386"
file /bin/ls | grep -q 64-bit && ARCH="amd64"

# Select a reasonable default system
RELEASE="xenial"; EXT="20180105"
: "${system:=$RELEASE-$EXT/$ARCH}"

# Extract the architecture (everything after the last '/')
release="${system%/*}"; [ "$release" != "$system" ] && arch="${system##*/}";
arch="${arch:-$ARCH}"; system="$release"

# Extract the extension (everything after the first '-')
release="${system%%-*}"; [ "$release" != "$system" ] && ext="${system#*-}";

# Allow a simple "i386" or "amd64" requirement
if [ -z "$arch$ext" ]; then
  case $release in
    i386|amd64) arch="$release"; release="$RELEASE"; ext="$EXT";;
  esac
fi

# Require a valid architecture
if [ "$arch" != "i386" -a "$arch" != "amd64" ]; then
    echo "Invalid architecture: $arch"
    exit 1
fi

# The chroot would probably fail without this requirement
if [ "$ARCH" = "i386" -a "$arch" = "amd64" ]; then
    echo "Please build 64-bit systems on a 64-bit instance."
    exit 1
fi

### Confirm the version #######################################################

if $validate; then exit 0; fi
suffix=${ext:+-$ext}

# Make a data directory
data="/var/cache/encroot"
mkdir -p "$data"

# Look for Ubuntu on the web if necessary
if [ -z "$systemDir" ]; then

    # Guess the subdirectory
    case "$ext" in
        alpha-*|beta-*) dir="$ext";;
        *) dir="release${suffix}";;
    esac

    # Construct the page URL
    page="https://cloud-images.ubuntu.com/releases/$release/$dir/"

    # Download the info page
    if ! curl -A "$my_agent" -Lfs "$page" > "${data}/release.html"; then
        echo "Invalid system: ${release}${suffix}"
        exit 1
    fi

    # Extract the name of the release tarball
    pattern='<a href="([^"]*-'$arch'\.tar\.gz)">\1</a>'
    file=$(perl -ne "m[$pattern] && "'print "$1\n"' "$data/release.html")

    # The image name is different in old tarballs
    if echo "$file" | grep -q cloudimg; then
        image="$release-server-cloudimg-$arch.img"
        label="cloudimg-rootfs"
    else
        image="$release-server-uec-$arch.img"
        label="uec-rootfs"
    fi

    # Complain as early as possible
    if [ -z "$file" ]; then
        echo "No tarball for system."
        exit 1
    fi
fi

### Final warning #############################################################

if [ ! -e "${dev}" ]; then
    echo "No device: ${dev}"
    exit 1
fi

if ! $trust_me; then
    echo "This script will erase ${dev}; are you sure (yes/no)?"

    while true; do
        read -p "Confirm: " erase
        if [ "_${erase}" = "_yes" -o "_${erase}" = "_no" ]; then
            break;
        fi
        echo "Please answer \"yes\" or \"no\"."
    done

    if [ "_${erase}" != "_yes" ]; then
        echo "Not erasing."
        exit 1
    fi

    echo
fi

### Password reading ##########################################################

read_password() {
    trap "stty echo; exit 0" INT 0

    while true; do
        stty -echo;
        read -p "Password for slot $1: " password1; echo > $(tty)
        read -p "Confirm the password: " password2; echo > $(tty)
        if [ "_${password1}" != "_${password2}" ]; then
            echo "Inconsistent; please try again." > $(tty)
            continue;
        fi

        printf ${password1}
        stty echo;
        break
    done
}

text_filter=""

# Make the beginning of indented lines bold
if $fancy && ! $no_fonts; then
    text_filter="$text_filter| perl -pe 's|^( .{23})|\\033[1m\$1\\033[0m|'"
fi

# Use fancy underscore lines
if $fancy && ! $no_lines; then
    text_filter="$text_filter| perl -pe 's|^-+|$separator|'"
fi

eval cat "$text_filter" <<EOT
-------------------------------------------------------------------------------

Two secret passwords are needed for the encrypted filesystem. Random 128-bit
passwords can be generated by running this command on a local Unix system:

    openssl rand -hex 16

Paste them below, and write them like this on two small slips of paper:

    8ac5bc85    14e223f4    NOTE: Any of these keys will unlock the partition,
    834b2100    68ffdc68          so you would typically keep one for yourself
    2784cc06    e80ae348          and store the other in a safe place, just in
    caac18e9    ebe28786          case your wallet is stolen; or give each key
    -Slot-0-    -Slot-1-          to a single group member - revoke if needed.

Treat these notes like your home keys. That's probably better than trying to
memorize weak passwords. If your secrets are REALLY important, you can still
burn your sheet of paper and they won't get anything out of torturing you...

-------------------------------------------------------------------------------

EOT

# Get two passwords from the user
password0=$(read_password 0);
password1=$(read_password 1);

### Progress Bar ##############################################################

pbBarLength=74
set -o noglob

pbCountString="$(printf "%${pbBarLength}s" '')"
pbOtherString="$(printf "%${pbBarLength}s" '')"

if ! $fancy || $no_color; then
    pbCountString="$(echo "$pbCountString" | tr ' ' '#')"
    pbOtherString="$(echo "$pbOtherString" | tr ' ' '-')"
fi

show_progress() {
    local index total count other
    index=$1; total=$2

    if [ $index -gt $total ]; then
        index=$total
    fi

    count=$((pbBarLength*index/total))
    other=$((pbBarLength-count))

    printf "\r"
    set_display_mode 44
    printf "%s" "$(echo "$pbCountString" | cut -b 1-$count 2> /dev/null)"
    set_display_mode 40
    printf "%s" "$(echo "$pbOtherString" | cut -b 1-$other 2> /dev/null)"
    set_display_mode 0
    printf " %3d%%" $((100*index/total))
}

### Slow Jobs #################################################################

attempt=""
slowPid=""

kill_slow_job() {
    if [ -n "$slowPid" ]; then
        kill $slowPid 2> /dev/null || true;
        slowPid="";
    fi

    echo;
}

get_slow_index() { echo "0"; }
get_slow_total() { echo "100"; }
is_slow_reject() { [ $1 -lt $2 ]; }

run_slow_job() {
    local message; message=$1; shift
    local delay; delay=$1; shift
    local total stop index

    attempt=$((attempt+1))
    total=$(get_slow_total)
    stop=false
    index=0

    bold_printf "%s\n" "$message"
    hide_cursor;

    "$@" & slowPid=$!

    while ! $stop; do
        index=$(get_slow_index)
        [ -t 1 ] && show_progress $index $total
        ps $slowPid > /dev/null 2>&1 && sleep $delay || stop=true
    done

    if is_slow_reject $index $total; then
        show_progress $index $total
        if [ $attempt -lt 3 ]; then
            sleep 10
            run_slow_job "$message" "$delay" "$@"
            return
        fi
        bold_printf "\nFailed\n"
        slowPid=""
        exit 1
    fi

    show_progress $total $total
    bold_printf "\nOK\n"
    show_cursor;
    attempt=""
    slowPid=""
}

### Verification and cleanup ##################################################

dots() {
    set_display_mode "$BOLD"
    perl -e 'print $ARGV[0], "."x(45-length($ARGV[0])), "... "' "$*";

    if $no_color; then
        set_display_mode "$NORMAL"
    else
        set_display_mode "$BOLD_RED"
    fi
}

check() {
    # Set the variables
    local options message program value
    options="--keyring=$home/uecimage.gpg"
    message="$1"; program="$2" sums="$3"

    # Print the message
    bold_printf "$message"

    # Download the checksum files (ignore missing files)
    curl -A "$my_agent" -Lfs "$page/$sums.gpg" > "$data/$sums.gpg"
    if ! curl -A "$my_agent" -Lfs "$page/$sums" > "$data/$sums"; then
        warn "N/A"
        return
    fi

    # Verify the signature
    if ! gpgv $options "$data/$sums.gpg" "$data/$sums" 2> /dev/null; then
        warn "Evil"
        exit 1;
    fi

    # Verify the checksum
    if grep "$file" "$data/$sums" | (cd $data; $program --check --status); then
        tick "OK"
    else
        set_display_mode "$BOLD_RED"
        printf "Failed"
        set_display_mode "$NORMAL"
        echo "  (You may need to clear /var/cache/encroot/)"
        exit 1;
    fi
}

cleanup() {
    trap "" INT  # Ignore a second Ctrl-C
    trap - 0     # No recursion on exit

    kill_slow_job;
    set_display_mode "$NORMAL"
    print_separator;
    show_cursor;

    if [ "_${work#/tmp/tmp.}" = "_${work}" ]; then
        echo "Unexpected work directory; refusing to clean."
        exit 1
    fi

    dots "Cleaning up"
    umount -l "${work}/ubuntu" 2> /dev/null || true
    umount -l "${work}/boot" 2> /dev/null || true
    umount -l "${work}/root/dev/pts" 2> /dev/null || true
    umount -l "${work}/root/dev" 2> /dev/null || true
    umount -l "${work}/root/proc" 2> /dev/null || true
    umount -l "${work}/root/sys" 2> /dev/null || true
    umount -l "${work}/root/boot" 2> /dev/null || true
    umount -l "${work}/root" 2> /dev/null || true
    umount -l "${work}" 2> /dev/null || true
    rm -rf "${work}"

    cryptsetup luksClose $name 2> /dev/null || true
    stty echo; tick "done"
    exit $exitValue
}

### Data fetching #############################################################

echo_size() {
    local size unit number;
    size="${1}0"

    # Express the size in higher multiples...
    for unit in bytes KiB MiB GiB TiB; do
        if [ $size -ge 10240 ]; then size=$((size/1024)); else break; fi
    done

    # Get the integer part
    number=${size%?};

    # Add a decimal for higher multiples
    if [ _$unit != _bytes ]; then
        number="$number.${size#$number}";
    elif [ "$number" = 1 ]; then
        unit=byte
    fi

    # Echo the result
    set_display_mode "$BOLD_BLUE"
    echo "$number $unit"
    set_display_mode "$NORMAL"
}

# Use an Ubuntu tarball by default
if [ -z "$systemDir" ]; then

    # Download the tarball if necessary
    if [ ! -e "${data}/$file" ]; then
        echo; print_separator
        LANG="C" wget -P "${data}" "${page}${file}"
    fi

    # Verify the checksums
    echo; print_separator
    check "Checking SHA256... " sha256sum SHA256SUMS
    check "Checking SHA1..... " sha1sum SHA1SUMS
    check "Checking MD5...... " md5sum MD5SUMS

    # Get the unpacked image size
    bold_printf "Checking size..... "
    total=$(tar tfzv "${data}/${file}" ${image} | head -1 | awk '{print $3}')
    echo_size $total;
fi

### Image unpacking ###########################################################

# Create a work directory
work="$(mktemp --directory)"
trap cleanup INT 0

# Ubuntu 16.04 (Xenial) marks the entire file hierarchy shared,
# and you are not allowed to move mounts in shared parents...
mount --make-private --bind "${work}" "${work}"

# Mount system directory if necessary
if [ -z "$systemDir" ]; then
    echo; print_separator;

    # Unpack the filesystem
    touch ${work}/${image}
    get_slow_index() { ls -la "${work}/${image}" | awk '{print $5}'; }
    get_slow_total() { echo $total; }
    run_slow_job "Unpacking image" 1 \
        tar xfz "${data}/${file}" -C "${work}" ${image}

    # Mount the unpacked image
    mkdir "${work}/ubuntu"
    mount -o loop,ro "${work}/${image}" "${work}/ubuntu"
    systemDir="${work}/ubuntu"
fi

### Disk formatting ###########################################################

bootLabel="bootfs"

# If we have a system directory:
if [ -n "$systemDir" ]; then

    # Copy any existing label from a mounted directory
    systemDev=$(mount | grep " on $systemDir " | awk '{print $1}')
    if [ -n "$systemDev" ]; then
        label=$(e2label "$systemDev")
    fi

    # Copy the UUID as well, if we can get it
    code='/UUID="?(\S+?)"? / && print "$1\n"'
    uuid=$(/sbin/blkid "$systemDev" | perl -ne "$code")

    # Use a default label if necessary
    if [ -z "$label" ]; then
        label="rootfs"
    fi
fi

# Partition the volume (leaving some space for GRUB)
print_header "Making partitions"
/sbin/sfdisk -L -uS $dev <<EOT
64 ${bootsize} 83 *
$((64+bootsize))
EOT

# Give udevd some time to mknod ${dev}1
sleep 2

# Create an ordinary Ext3 filesystem in the first partition
print_header "Creating ext3 filesystem on ${dev}1"
/sbin/mkfs -t ext3 -m 1 -L "${bootLabel}" "${dev}1"

# Find a free luks device
print_separator; dots "Formatting encrypted area"
num=1; while [ -e "/dev/mapper/luks${num}" ]; do num="$((num+1))"; done
name="luks${num}"

# Temporarily save the passwords; they will probably never reach the disk
mask=$(umask); umask 077
printf "$password0" > "${work}/pw0.txt"
printf "$password1" > "${work}/pw1.txt"
umask $mask

# Create an encrypted area in the second partition
cryptsetup luksFormat -q --key-size=256 ${dev}2 "${work}/pw0.txt"; tick "OK"
cryptsetup luksAddKey -q --key-file="${work}/pw0.txt" ${dev}2 "${work}/pw1.txt"
cryptsetup luksOpen --key-file="${work}/pw0.txt" ${dev}2 $name

# Shred the passwords
shred --remove "${work}/pw0.txt"
shred --remove "${work}/pw1.txt"

# Check the type of our original filesystem
fsType=$(df -T "$systemDir" | tail -1 | awk '{print $2}')

# Create a similar filesystem
print_header "Creating $fsType filesystem on ${dev}2"
mkfs -t $fsType "/dev/mapper/$name"

# Add a label to find the root during boot
if $big_boot; then
    /sbin/e2label "${dev}1" "${label}"
else
    /sbin/e2label "/dev/mapper/$name" "${label}"
fi

# Use the original UUID if we have it
if [ -n "$uuid" ]; then
    /sbin/tune2fs -U "$uuid" "/dev/mapper/$name"
fi

### Encrypted filesystem ######################################################

print_size() {
    df -k "$1" | tail -1 | awk '{print $3}'
}

# Mount the encrypted filesystem
print_separator
mkdir "${work}/root"
mount /dev/mapper/$name "${work}/root"

# Calculate a range for the progress bar
dots "Checking total system size"
totalSize=$(du -skx "$systemDir" | awk '{print $1}')
startSize=$(du -skx "${work}/root" | awk '{print $1}')
totalDiff=$((totalSize - startSize))
echo_size $((1024*totalDiff)); echo

# The df size contains a lot of overhead
sizeOffset=$(print_size "${work}/root");

# Define functions for the progress bar
get_slow_total() { echo $totalDiff; }
get_slow_index() { echo $(($(print_size "${work}/root") - sizeOffset)); }
is_slow_reject() {
    # Don't even try if we're copying a running system
    if [ "$systemDir" = "/" ]; then return 1; fi

    # Skip directories, since their exact sizes are unpredictable
    (cd "$systemDir"; find . -xdev \! -type d -ls | awk '{print $11, $7}' ) \
        | sort > "${work}/system.ls"
    (cd "${work}/root"; find . -xdev \! -type d -ls | awk '{print $11, $7}' ) \
        | sort > "${work}/root.ls"
    ! diff "${work}/system.ls" "${work}/root.ls" > /dev/null;
}

# Install Ubuntu on the encrypted filesystem
run_slow_job "Copying lots of data to ${dev}2" 5 \
    rsync --archive --hard-links --one-file-system \
        "$systemDir/" "${work}/root/"

### Boot support ##############################################################

echo; print_separator

# Select suitable boot/root devices
bootDevice="LABEL=$bootLabel"
luksDevice="UUID=$(cryptsetup luksUUID ${dev}2)"
rootDevice="LABEL=$label"

if $big_boot; then

    # Use partition 1 as root
    umount "${work}/root";
    mount "${dev}1" "${work}/root"

    # The overhead is different for a smaller partition
    sizeOffset=$(print_size "${work}/root");

    # Install Ubuntu on it
    run_slow_job "Copying data for the boot partition" 5 \
        rsync --archive --hard-links --one-file-system \
            "$systemDir/" "${work}/root/"
else

    # Prepare to boot from an initramfs
    dots "Preparing /boot (${dev}1)"

    # Move all /boot files to the boot partition
    mkdir "${work}/boot"; mount "${dev}1" "${work}/boot"
    rsync --archive "${work}/root/boot/" "${work}/boot"
    rm -rf "${work}/root/boot/"*

    # Put the boot partition where it belongs
    mount --move "${work}/boot" "${work}/root/boot"
    tick "OK"
fi

# Give the user a chance to fix things before we continue
if [ -n "$fix_hook" ]; then
    "$fix_hook" "init" "${work}/root"
fi

###  Web server etc. ##########################################################

bozo_version=20190228
csum="4e1653cadb13068ceb6025daa1c93a5d44d4e6726a8fe91172f962958e4eafb6"
page="https://ftp.netbsd.org/pub/pkgsrc/distfiles/LOCAL_PORTS/"
file="bozohttpd-${bozo_version}.tar.bz2"
bozo="/usr/src/${file%.tar.bz2}"
unset bozo_packages

print_header "Downloading web server"

# Download the tarball if necessary
if [ ! -e "${data}/${file}" ]; then
    LANG="C" wget -P "${data}" "${page}${file}"
fi

# Verify its integrity
printf "Checking SHA256... "
if echo "$csum  ${data}/${file}" | sha256sum --check --status; then
    tick "OK"; echo
else
    warn "Evil"
    exit 1
fi

# We need a place to unpack it
mkdir -p ${work}/root/usr/src

# Unpack bozohttpd source code and adjust the Makefile
cat "${data}/${file}" | bunzip2 | tar -C "${work}/root/usr/src" -o -xf -
perl -i -p - "${work}/root${bozo}/Makefile.boot" <<- EOT
	s[^(LOCAL_CFLAGS=.*)][\$1 -D_GNU_SOURCE -Wno-unused-result]
	EOT

# Patch bozohttpd to add a missing header file
perl -i -p - "${work}/root${bozo}/ssl-bozo.c" <<- EOT
	s[^(#include <stdio.h>)][\$1\n#include <string.h>]
	EOT

demand() {
    if [ ! -e "${work}/root$1" ]; then
        bozo_packages="$bozo_packages ${1##*/}"
    fi
}

# Check which packages we need
demand /usr/share/doc/libc6-dev
demand /usr/share/doc/libssl-dev
demand /usr/bin/make
demand /usr/bin/gcc

if $big_boot; then
    cfg=".cfg"

    # Update the fstab file
    perl -i -pe 's[^\S+(\s+/\s)]['"$rootDevice"'$1]' "${work}/root/etc/fstab"

    # Ubuntu 17.10 (Artful) doesn't have ifupdown by default
    if [ ! -e "${work}/root/etc/network/interfaces.d" ]; then
        mkdir -p "${work}/root/etc/network/interfaces.d"
        cfg=""
    fi

    # Ubuntu 16.04 (Xenial) doesn't have the eth0.cfg file
    if ! chroot "${work}/root" /sbin/ifquery eth0 > /dev/null 2>&1; then
        cat > "${work}/root/etc/network/interfaces.d/eth0$cfg" <<- EOT
		iface eth0 inet dhcp
		auto eth0
		EOT
    fi

    # Copy the simple files into place
    bozo_target="${work}/root/"
    mkdir -p "${work}/root/etc/ssl/private/"
    cp "${cert}/boot.key" "${work}/root/etc/ssl/private/"
    mkdir -p "${work}/root/etc/ssl/certs/"
    cp "${cert}/boot.crt" "${work}/root/etc/ssl/certs/"

    # Check if the distro is using systemd or init
    if [ -e "${work}/root/lib/systemd/systemd" ]; then
        init="${work}/root/lib/systemd/systemd"
        udev="/lib/systemd/systemd-udevd"
    else
        init="${work}/root/sbin/init"
        udev="udevd"
    fi

    # Replace init or systemd with our own script
    rm "${init}"
    cp "${home}/init.sh" "${init}"
    chmod 755 "${init}"
    perl -i -p - "${init}" <<- EOT
	s[/sbin/init][${init##*/root}];
	s[/dev/sda2][$luksDevice];
	EOT

    # Copy pre_init.sh into place
    mkdir -p "${work}/root/etc/ec2"
    cp "${home}/pre_init.sh" "${work}/root/etc/ec2/"
    perl -i -p - "${work}/root/etc/ec2/pre_init.sh" <<- EOT
	s[^(pi_priv=).*][\$1"/etc/ssl/private/boot.key"];
	s[^(pi_cert=).*][\$1"/etc/ssl/certs/boot.crt"];
	s[^(pi_host=).*][\$1"$host"];
	s[^(pi_port=).*][\$1"$port"];
	s[udevd( --daemon)][$udev\$1];
	s[(pkill )udevd][\$1${udev##*/}];
	EOT
else

    # Update the fstab file
    rootDevice="/dev/mapper/cryptroot"
    perl -i -pe 's[^\S+(\s+/\s)]['"$rootDevice"'$1]' "${work}/root/etc/fstab"
    echo "$bootDevice /boot ext3" >> "${work}/root/etc/fstab"

    # Create the ${bozo_target} directory
    bozo_target="${work}/root/etc/initramfs-tools/boot/"
    mkdir -p ${bozo_target}

    # Copy the simple files into place
    cp "${cert}/boot.key" "${bozo_target}"
    cp "${cert}/boot.crt" "${bozo_target}"

    # Copy the cryptsetup hook
    cp "${home}/cryptsetup" "${work}/root/etc/initramfs-tools/hooks/"
    perl -i -p - "${work}/root/etc/initramfs-tools/hooks/cryptsetup" <<- EOT
	s[/dev/sda2][$luksDevice];
	EOT

    # Copy cryptsetup.sh
    mkdir -p "${work}/root/etc/ec2"
    cp "${home}/cryptsetup.sh" "${work}/root/etc/initramfs-tools/boot/"
    perl -i -p - "${work}/root/etc/initramfs-tools/boot/cryptsetup.sh" <<- EOT
	s[^(cs_host=).*][\$1"$host"];
	s[^(cs_port=).*][\$1"$port"];
	EOT

fi

# Copy all bozohttpd-related files
cp "${home}/make_bozo_dir.sh" "${bozo_target}"
cp "${home}/index.html" "${bozo_target}"
cp "${home}/activate.cgi" "${bozo_target}"
cp "${home}/hiding.gif" "${bozo_target}"

### Grub-Dependent Fix ########################################################

# The HVM version of Debian 7 (Wheezy) doesn't have this
if [ -e "$work/root/boot/grub/menu.lst" ]; then

# On Debian Wheezy, menu.lst is a symbolic link to grub.cfg
menuFile="$work/root$(chroot $work/root readlink -f /boot/grub/menu.lst)"

# Update GRUB files to use the actual root device
for file in "$menuFile" "$work/root/etc/grub.d/40_custom"; do
    if [ ! -e "$file" ]; then continue; fi
    perl -i -p - "$file" <<- EOT
	s[/dev/(sda|xvda)\b][$rootDevice];
	s[\(hd0\)][(hd0,0)];
	EOT
done

# Grab initrd and kernel for the first boot entry
initrd=$(grep '^[[:space:]]*initrd' "$menuFile" | head -1 | awk '{print $2}')
kernel=$(grep -E '^[[:space:]]*(kernel|linux)[[:space:]]' "$menuFile" \
    | head -1 | awk '{print $2}')

# These symlinks are sometimes incorrect
rm -f "${work}/root/initrd.img.old"
rm -f "${work}/root/vmlinuz.old"
rm -f "${work}/root/initrd.img"
rm -f "${work}/root/vmlinuz"

# Use the extracted initrd and kernel instead
ln -s "$initrd" "${work}/root/initrd.img"
ln -s "$kernel" "${work}/root/vmlinuz"

fi

### More General Stuff ########################################################

# Temporarily use a working /etc/resolv.conf
resolv="${work}/root/etc/resolv.conf"
mv "${resolv}" "${resolv}.old" 2>/dev/null || true
cp "/etc/resolv.conf" "${work}/root/etc/"

# Debian 7 (Wheezy) doesn't have GRUB by default
if [ -d "${work}/root/boot/grub" ]; then
    grub_command="rm -f /boot/grub/device.map
	dpkg-reconfigure grub-pc
	grub-install $dev"
else
    grub_command="# Install without updating initramfs
	mv /usr/sbin/update-initramfs /usr/sbin/update-initramfs.old
	touch /usr/sbin/update-initramfs
	chmod a+x /usr/sbin/update-initramfs
	apt-get -y install grub-pc
	mv /usr/sbin/update-initramfs.old /usr/sbin/update-initramfs"
fi

# Prepare extra network interfaces for convenience
if [ "$if_count" -gt 1 ]; then
    interfaces="${work}/root/etc/network/interfaces"
    if_index=1

    printf "\n# Other network interfaces\n" >> "$interfaces"
    while [ "$if_index" -lt "$if_count" ]; do
        echo "auto eth${if_index}" >> "$interfaces"
        echo "iface eth${if_index} inet dhcp" >> "$interfaces"
        if_index=$((if_index+1))
    done
fi

# Whatever happens, don't ask questions
export DEBIAN_FRONTEND=noninteractive
update_options=""

# Preconfigure stuff to get something reasonable
chroot "${work}/root/" debconf-set-selections <<- EOT
	grub-pc grub-pc/install_devices string $dev
	EOT

# Prepare the initial filesystem
run_block "Mounting and updating" <<- EOT
	mount -t devtmpfs udev /dev/
	mount -t devpts devpts /dev/pts/
	mount -t proc proc /proc/
	mount -t sysfs sysfs /sys/
	localedef -f UTF-8 -i en_US --no-archive en_US.utf8
	rm -f /var/cache/apt/pkgcache.bin
	rm -f /var/cache/apt/srcpkgcache.bin
	apt-get -y update
	EOT

# Install GRUB for booting with hardware-based virtualization
run_block "Installing GRUB" <<- EOT
	${grub_command}
	EOT

# Install SSL certificates without updating initramfs
run_block "Installing SSL certificates" <<- EOT
	mv /usr/sbin/update-initramfs /usr/sbin/update-initramfs.old
	touch /usr/sbin/update-initramfs
	chmod a+x /usr/sbin/update-initramfs
	apt-get -y install ssl-cert < /dev/null
	mv /usr/sbin/update-initramfs.old /usr/sbin/update-initramfs
	EOT

run_block "Installing web server dependencies" <<- EOT
	apt-get -y install${bozo_packages}
	EOT

# Install bozohttpd by building it from source code
run_block "Installing web server" <<- EOT
	(cd "${bozo}" && make -f Makefile.boot && gzip bozohttpd.8)
	install --strip "${bozo}/bozohttpd" /usr/sbin/
	cp "${bozo}/bozohttpd.8.gz" /usr/share/man/man8/
	apt-cache -i depends libssl-dev | awk '/ l/{print \$2}' > libssl.txt
	apt-get -y install \$(cat libssl.txt && rm libssl.txt)
	apt-get -y --auto-remove remove${bozo_packages}
	EOT

# Prepare things for the "Big Boot" option
$big_boot && run_block "Preparing for Big Boot" <<- EOT
	adduser --system --group --no-create-home bozo
	/bin/sh make_bozo_dir.sh /var/bozo
	chown -R bozo:bozo /var/bozo
	rm make_bozo_dir.sh index.html activate.cgi hiding.gif
	chown root:ssl-cert /etc/ssl/private/boot.key
	chmod 640 /etc/ssl/private/boot.key
	apt-get -y install ifupdown
	EOT

# Prepare things for the initramfs variety
$ram_boot && run_block "Preparing for initramfs" <<- EOT
	chown root:ssl-cert /etc/initramfs-tools/boot/boot.key
	chmod 640 /etc/initramfs-tools/boot/boot.key
	ln -s /usr/sbin/bozohttpd /etc/initramfs-tools/boot/
	ln -s . /boot/boot
	EOT

# Configure the keyboard since Jessie insists...
run_block "Configuring non-existent keyboard" <<- EOT
	mount -t tmpfs tmpfs /proc
	mkdir -p /proc/bus/input
	touch /proc/bus/input/devices
	mount -t tmpfs tmpfs /sys
	mkdir -p /sys/bus/usb/devices/0:0
	touch /sys/bus/usb/devices/0:0/bInterfaceClass
	touch /sys/bus/usb/devices/0:0/bInterfaceSubClass
	touch /sys/bus/usb/devices/0:0/bInterfaceProtocol
	apt-get -y install keyboard-configuration
	umount /proc /sys
	EOT

# Update configuration files to enable cryptsetup
if $ram_boot; then

    # Check which version of the cryptsetup package we're going to use
    version=$(chroot ${work}/root apt-cache show --no-all-versions cryptsetup \
        | grep "^Version:" | awk '{print $2}')

    # Later versions want CRYPTSETUP=y in a different location
    if dpkg --compare-versions "${version}" lt "2:1.7.3-3"; then
        configFile="${work}/root/etc/initramfs-tools/conf.d/cryptroot"
    else
        update_options="${update_options} -o Dpkg::options::=--force-confdef"
        configDir="${work}/root/etc/cryptsetup-initramfs"
        configFile="${configDir}/conf-hook"
        mkdir -p "${configDir}"
    fi

    # Force cryptsetup on initramfs
    echo "export CRYPTSETUP=y" >> "${configFile}"

fi

# Some versions of Ubuntu already have cryptsetup
if [ ! -e "${work}/root/sbin/cryptsetup" ]; then
    update_command="apt-get -y${update_options} install cryptsetup"
else
    update_command="update-initramfs -u"
fi

# Trigger an initramfs update and clean up
run_block "Generating initramfs and unmounting" <<- EOT
	${update_command}
	apt-get -y clean
	mv /etc/resolv.conf.old /etc/resolv.conf 2> /dev/null || true
	umount /dev/pts
	umount /dev
	umount /proc
	umount /sys
	EOT

# Give the user a chance to fix things before we exit
if [ -n "$fix_hook" ]; then
    "$fix_hook" "exit" "${work}/root"
fi

exitValue=0

###############################################################################
