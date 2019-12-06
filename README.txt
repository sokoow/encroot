-------------------------------------------------------------------------------
This explains the use of encrypted EBS-backed root filesystems in Amazon EC2.
Some of the code was originally written to allow use of EBS-backed instances
before Amazon released that feature. 1.5 years later, the original method is
now obsolete. However, any paranoid people out there may still be interested
in a working encryption layer. Encrypting the whole filesystem is conceptually
simpler than having to deal with separate encrypted volumes, and you can stop
worrying about potential secrets leaking through configuration or log files.

Of course, the hardware is still physically beyond your control, so it is up
to you to decide whether encryption adds any real value. On the other hand,
these steps should make it easy to construct your own instance, and you never
know if some sensitive backup tape will end up in the wrong hands.

                                     - Henrik Gulbrandsen <henrik@gulbra.net>
                                               2011-04-18

-------------------------------------------------------------------------------
I have updated the text below to match current reality. It is still valid, but
you should know that it only shows what you could do three years ago, which
was to create an encrypted classic EC2 instance with a clean Ubuntu system.

Today, you can also create Debian systems, clone an existing instance, start
VPC instances with multiple network interfaces and groups, use an IP address
as the "domain" if you really want to, add extra call parameters for advanced
EC2 features, and hook in your own script to handle a favorite Linux distro.
At the very least, you should probably look up the --name and --size options.

You can also install Encroot on instances with "./configure && make install",
which may be a good idea if you intend to use it regularly.

For more detailed info, please read the encroot(1) and awsapi(1) man pages.

                                     - Henrik Gulbrandsen <henrik@gulbra.net>
                                               2014-06-05

-------------------------------------------------------------------------------

This was tested with ami-41e0b93b (64-bit EBS us-east-1 - Ubuntu 16.04 LTS)
See https://help.ubuntu.com/community/UEC/Images for info on Ubuntu images.
Latest Xenial Xerus: https://uec-images.ubuntu.com/releases/xenial/release/

 A. In this setup, the decryption password is given via HTTPS. You will need
    an SSL certificate for the web server. A self-signed certificate may be
    even better than an official one, since your private key will be stored
    in the unencrypted partition, and this is not a public service anyway.
    If you don't know how to generate a self-signed certificate, have a look
    at the "SSL.txt" file. The remaining text assumes that you have stored
    your certificate as "boot.crt" and the private key as "boot.key".

 B. You may want to have a separate subdomain for the password page, so your
    ordinary web visitors don't find it. It will only be up for the minute
    it takes you to enter the password, but it's not intended for high load.
    Allocate a new Elastic IP and update your DNS to get the new subdomain.
    For example, you may want to add boot.example.com to the DNS records.

 C. The instructions below will create a system based on Ubuntu 16.04 LTS.
    Add "--system artful" to the command in step 6 if you want Artful
    instead of Xenial. The "--big-boot" option enables an alternative way of
    booting the instance, which installs a full Ubuntu system on /dev/xvda1.
    In this case, no changes are made to the system stored on the encrypted
    /dev/xvda2 partition. In theory, this will allow you to install any type
    of Linux distro there, instead of being limited to Ubuntu (or Debian).
    The downside is that /dev/xvda1 must be updated separately in that case.

-------------------------------------------------------------------------------

 1. Launch a new Ubuntu instance, so you don't delete anything important.
    This is just a build server, but the encrypted instance will have the
    same SSH key pair, instance type, availability zone, and architecture
    as this server, so you want to select them now.

 2. Connect to your Ubuntu instance and install cryptsetup:
      sudo apt-get -y install cryptsetup

 3. Upload all necessary files to a directory on the Ubuntu instance:
      activate.cgi                - password-fetching CGI script
      awsapi                      - used by the encroot script
      boot.crt                    - SSL certificate for the boot partition
      boot.key                    - private SSL key for the boot partition
      cryptsetup                  - initramfs hook script
      cryptsetup.sh               - initramfs cryptsetup replacement
      encroot                     - handles all necessary calls to the EC2 API
      hiding.gif                  - animated GIF used to hide text
      index.html                  - page that redirects to activate.cgi
      init.sh                     - script replacing /sbin/init in a Big Boot
      make_bozo_dir.sh            - bozohttpd home setup script
      make_encrypted_distro.sh    - does all the work on an attached volume
      pre_init.sh                 - script that gets the password in a Big Boot
      uecimage.gpg                - public key for Ubuntu images

 4. To avoid a lot of unnecessary manual work, put your AWS "Secret Access Key"
    and "Access Key ID" in the .awsapirc file as explained by "awsapi --man":
      touch ~/.awsapirc; chmod 600 ~/.awsapirc; nano ~/.awsapirc
      secretAccessKey: <your-secret-access-key>
      accessKeyId: <your-access-key-id>

 5. Create a security group for the encrypted instance. This group must allow
    HTTPS access, since this is how you will enter the password.

 6. Now, something like this should create and launch the instance for you:
    ./encroot --group "Security Group" boot.example.com

 7. The script will ask you for two passwords. Just follow the instructions.
    Expect a total running time of around 10 minutes on a micro instance.

 8. Visit https://boot.example.com/ in your web browser to unlock your root.
    The script automatically associates any Elastic IP address that this domain
    points to, but you must do this yourself the next time you boot the server.
    Once you have entered the decryption password, the system should boot.

 9. Don't forget to terminate your build instance when you're finished.

-------------------------------------------------------------------------------
