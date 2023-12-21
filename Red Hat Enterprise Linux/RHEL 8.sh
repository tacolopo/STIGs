#!/bin/bash

echo "Replace 'user' and '/home/directory' with your information"

echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"
echo "Security Technical Implementation Guide (STIG) RHEL 8 V1R11"
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010000"
echo "cat /etc/redhat-release"
cat /etc/redhat-release
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010010"
echo "yum history list | more"
yum history list | more
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010020"
echo "fips-mode-setup --check"
fips-mode-setup --check
echo "grub2-editenv list | grep fips"
grub2-editenv list | grep fips
echo "cat /proc/sys/crypto/fips_enabled"
cat /proc/sys/crypto/fips_enabled
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010030"
echo "blkid"
blkid
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010040"
echo "grep -ir banner /etc/ssh/sshd_config*"
grep -ir banner /etc/ssh/sshd_config*
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010050"
echo "grep banner-message-text /etc/dconf/db/local.d/*"
grep banner-message-text /etc/dconf/db/local.d/*
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010060"
echo "cat /etc/issue"
cat /etc/issue
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010070"
echo "grep -E '(auth.*|authpriv.*|daemon.*)' /etc/rsyslog.conf"
grep -E '(auth.*|authpriv.*|daemon.*)' /etc/rsyslog.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010090"
echo "openssl x509 -text -in /etc/sssd/pki/sssd_auth_ca_db.pem"
openssl x509 -text -in /etc/sssd/pki/sssd_auth_ca_db.pem
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010110"
echo "grep -i crypt /etc/login.defs"
grep -i crypt /etc/login.defs 
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010120"
echo "cut -d: -f2 /etc/shadow"
cut -d: -f2 /etc/shadow
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010130"
echo "grep -E "^SHA_CRYPT_" /etc/login.defs"
grep -E "^SHA_CRYPT_" /etc/login.defs
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010140"
echo "grep -iw grub2_password /boot/efi/EFI/redhat/user.cfg"
grep -iw grub2_password /boot/efi/EFI/redhat/user.cfg
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010150"
echo "grep -iw grub2_password /boot/grub2/user.cfg"
grep -iw grub2_password /boot/grub2/user.cfg
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010151"
echo "grep sulogin-shell /usr/lib/systemd/system/rescue.service"
grep sulogin-shell /usr/lib/systemd/system/rescue.service
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010160"
echo "grep password /etc/pam.d/password-auth | grep pam_unix"
grep password /etc/pam.d/password-auth | grep pam_unix
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010161"
echo "ls -al /etc/*.keytab"
ls -al /etc/*.keytab
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010162"
echo "yum list installed krb5-workstation"
yum list installed krb5-workstation
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010170"
echo "getenforce"
getenforce
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010171"
echo "yum list installed policycoreutils"
yum list installed policycoreutils
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010190"
echo "find / -type d \( -perm -0002 -a ! -perm -1000 \) -print 2>/dev/null"
find / -type d \( -perm -0002 -a ! -perm -1000 \) -print 2>/dev/null
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010200"
echo "grep -ir clientalivecountmax /etc/ssh/sshd_config*"
grep -ir clientalivecountmax /etc/ssh/sshd_config*
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010210"
echo "stat -c "%a %n" /var/log/messages"
stat -c "%a %n" /var/log/messages
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010220"
echo "stat -c "%U" /var/log/messages"
stat -c "%U" /var/log/messages
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010230"
echo "stat -c "%G" /var/log/messages"
stat -c "%G" /var/log/messages
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010240"
echo "stat -c "%a %n" /var/log"
stat -c "%a %n" /var/log
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010250"
echo "stat -c "%U" /var/log"
stat -c "%U" /var/log
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010260"
echo "stat -c "%G" /var/log"
stat -c "%G" /var/log
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010290"
echo "grep -i macs /etc/crypto-policies/back-ends/opensshserver.config"
grep -i macs /etc/crypto-policies/back-ends/opensshserver.config
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010291"
echo "grep -i ciphers /etc/crypto-policies/back-ends/opensshserver.config"
grep -i ciphers /etc/crypto-policies/back-ends/opensshserver.config
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010292"
echo "grep -i ssh_use_strong_rng /etc/sysconfig/sshd"
grep -i ssh_use_strong_rng /etc/sysconfig/sshd
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010293"
echo "grep -i opensslcnf.config /etc/pki/tls/openssl.cnf"
grep -i opensslcnf.config /etc/pki/tls/openssl.cnf
echo "update-crypto-policies --show"
update-crypto-policies --show
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010294"
echo "grep -i  MinProtocol /etc/crypto-policies/back-ends/opensslcnf.config"
grep -i  MinProtocol /etc/crypto-policies/back-ends/opensslcnf.config
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010295"
echo "grep -io +vers.*  /etc/crypto-policies/back-ends/gnutls.config"
grep -io +vers.*  /etc/crypto-policies/back-ends/gnutls.config
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010300"
echo "find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -exec ls -l {} \;"
find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -exec ls -l {} \;
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010310"
echo "find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -exec ls -l {} \;"
find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -exec ls -l {} \;
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010320"
echo "find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -exec ls -l {} \;"
find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -exec ls -l {} \;
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010330"
echo "find -L /lib /lib64 /usr/lib /usr/lib64 -perm /022 -type f -exec ls -l {} \;"
find -L /lib /lib64 /usr/lib /usr/lib64 -perm /022 -type f -exec ls -l {} \;
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010340"
echo "find -L /lib /lib64 /usr/lib /usr/lib64 ! -user root -exec ls -l {} \;"
find -L /lib /lib64 /usr/lib /usr/lib64 ! -user root -exec ls -l {} \;
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010350"
echo "find -L /lib /lib64 /usr/lib /usr/lib64 ! -group root -exec ls -l {} \;"
find -L /lib /lib64 /usr/lib /usr/lib64 ! -group root -exec ls -l {} \;
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010360"
echo "ls -al /etc/cron.* | grep aide"
ls -al /etc/cron.* | grep aide
echo "grep aide /etc/crontab /var/spool/cron/root"
grep aide /etc/crontab /var/spool/cron/root
echo "more /etc/cron.daily/aide"
more /etc/cron.daily/aide
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010370"
echo "grep -E '^\[.*\]|gpgcheck' /etc/yum.repos.d/*.repo"
grep -E '^\[.*\]|gpgcheck' /etc/yum.repos.d/*.repo
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010371"
echo "grep -i localpkg_gpgcheck /etc/dnf/dnf.conf"
grep -i localpkg_gpgcheck /etc/dnf/dnf.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010372"
echo "sysctl kernel.kexec_load_disabled"
sysctl kernel.kexec_load_disabled
echo "grep -r kernel.kexec_load_disabled /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf"
grep -r kernel.kexec_load_disabled /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010373"
echo "sysctl fs.protected_symlinks"
sysctl fs.protected_symlinks
echo "grep -r fs.protected_symlinks /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf"
grep -r fs.protected_symlinks /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf 
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010374"
echo "sysctl fs.protected_hardlinks"
sysctl fs.protected_hardlinks
echo "grep -r fs.protected_hardlinks /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf"
grep -r fs.protected_hardlinks /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010375"
echo "sysctl kernel.dmesg_restrict"
sysctl kernel.dmesg_restrict
echo "grep -r kernel.dmesg_restrict /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf"
grep -r kernel.dmesg_restrict /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010376"
echo "sysctl kernel.perf_event_paranoid"
sysctl kernel.perf_event_paranoid
echo "grep -r kernel.perf_event_paranoid /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf"
grep -r kernel.perf_event_paranoid /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010380"
echo "grep -i nopasswd /etc/sudoers /etc/sudoers.d/*"
grep -i nopasswd /etc/sudoers /etc/sudoers.d/*
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010381"
echo "grep -i !authenticate /etc/sudoers /etc/sudoers.d/*"
grep -i !authenticate /etc/sudoers /etc/sudoers.d/*
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010390"
echo "yum list installed openssl-pkcs11"
yum list installed openssl-pkcs11
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010400"
echo 'grep certificate_verification /etc/sssd/sssd.conf /etc/sssd/conf.d/*.conf | grep -v "^#"'
grep certificate_verification /etc/sssd/sssd.conf /etc/sssd/conf.d/*.conf | grep -v "^#"
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010410"
echo "yum list installed opensc"
yum list installed opensc
echo "opensc-tool --list-drivers | grep -i piv"
opensc-tool --list-drivers | grep -i piv
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010420"
echo "dmesg | grep NX"
dmesg | grep NX
echo "less /proc/cpuinfo | grep -i flags"
less /proc/cpuinfo | grep -i flags
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010421"
echo "grub2-editenv list | grep page_poison"
grub2-editenv list | grep page_poison
echo "grep page_poison /etc/default/grub"
grep page_poison /etc/default/grub
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010422"
echo "grub2-editenv list | grep vsyscall"
grub2-editenv list | grep vsyscall
echo "grep vsyscall /etc/default/grub"
grep vsyscall /etc/default/grub
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010423"
echo "grub2-editenv list | grep slub_debug"
grub2-editenv list | grep slub_debug
echo "grep slub_debug /etc/default/grub"
grep slub_debug /etc/default/grub
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010430"
echo "sysctl kernel.randomize_va_space"
sysctl kernel.randomize_va_space
echo "grep -r kernel.randomize_va_space /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf"
grep -r kernel.randomize_va_space /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010440"
echo "grep -i clean_requirements_on_remove /etc/dnf/dnf.conf"
grep -i clean_requirements_on_remove /etc/dnf/dnf.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010450"
echo "sestatus"
sestatus
echo "grep -i "selinuxtype" /etc/selinux/config | grep -v '^#'"
grep -i "selinuxtype" /etc/selinux/config | grep -v '^#'
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010460"
echo "find / -name shosts.equiv"
find / -name shosts.equiv
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010470"
echo "find / -name '*.shosts'"
find / -name '*.shosts'
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010471"
echo "systemctl is-enabled rngd"
systemctl is-enabled rngd
echo "systemctl is-active rngd"
systemctl is-active rngd
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010480"
echo "ls -l /etc/ssh/*.pub"
ls -l /etc/ssh/*.pub
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010490"
echo "ls -l /etc/ssh/ssh_host*key"
ls -l /etc/ssh/ssh_host*key
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010500"
echo "grep -ir strictmodes /etc/ssh/sshd_config*"
grep -ir strictmodes /etc/ssh/sshd_config*
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010520"
echo "grep -ir IgnoreUserKnownHosts /etc/ssh/sshd_config*"
grep -ir IgnoreUserKnownHosts /etc/ssh/sshd_config*
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010521"
echo "grep -ir KerberosAuthentication  /etc/ssh/sshd_config*"
grep -ir KerberosAuthentication  /etc/ssh/sshd_config*
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010540"
echo "grep /var /etc/fstab"
grep /var /etc/fstab
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010541"
echo "grep /var/log /etc/fstab"
grep /var/log /etc/fstab
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010542"
echo "grep /var/log/audit /etc/fstab"
grep /var/log/audit /etc/fstab
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010543"
echo "grep /tmp /etc/fstab"
grep /tmp /etc/fstab
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010550"
echo "grep -ir PermitRootLogin /etc/ssh/sshd_config*"
grep -ir PermitRootLogin /etc/ssh/sshd_config*
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010561"
echo "systemctl is-enabled rsyslog"
systemctl is-enabled rsyslog
echo "systemctl is-active rsyslog"
systemctl is-active rsyslog
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010570, RHEL-08-010600, RHEL-08-010610, RHEL-08-010620"
echo "awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1,$3,$6}' /etc/passwd"
awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1,$3,$6}' /etc/passwd
echo "more /etc/fstab"
more /etc/fstab
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010571"
echo "mount | grep '\s/boot\s'"
mount | grep '\s/boot\s'
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010580"
echo "mount | grep '^/dev\S* on /\S' | grep --invert-match 'nodev'"
mount | grep '^/dev\S* on /\S' | grep --invert-match 'nodev'
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010590"
echo "awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1,$3,$6}' /etc/passwd"
awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1,$3,$6}' /etc/passwd
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010630"
echo "grep nfs /etc/fstab | grep noexec"
grep nfs /etc/fstab | grep noexec
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010640"
echo "grep nfs /etc/fstab | grep nodev"
grep nfs /etc/fstab | grep nodev
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010650"
echo "grep nfs /etc/fstab | grep nosuid"
grep nfs /etc/fstab | grep nosuid
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010660"
echo "find /boot -xdev -type f -perm -0002 -print"
find /boot -xdev -type f -perm -0002 -print
echo "find /home -xdev -type f -perm -0002 -print"
find /home -xdev -type f -perm -0002 -print
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010670"
echo "systemctl status kdump.service"
systemctl status kdump.service
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010671"
echo "sysctl kernel.core_pattern"
sysctl kernel.core_pattern
echo "grep -r kernel.core_pattern /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf"
grep -r kernel.core_pattern /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010672"
echo "systemctl status systemd-coredump.socket"
systemctl status systemd-coredump.socket
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010673"
echo "grep -r -s '^[^#].*core' /etc/security/limits.conf /etc/security/limits.d/*.conf"
grep -r -s '^[^#].*core' /etc/security/limits.conf /etc/security/limits.d/*.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010674"
echo "grep -i storage /etc/systemd/coredump.conf"
grep -i storage /etc/systemd/coredump.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010675"
echo "grep -i ProcessSizeMax /etc/systemd/coredump.conf"
grep -i ProcessSizeMax /etc/systemd/coredump.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010680"
echo "grep hosts /etc/nsswitch.conf"
grep hosts /etc/nsswitch.conf
echo "ls -al /etc/resolv.conf"
ls -al /etc/resolv.conf
echo "grep nameserver /etc/resolv.conf"
grep nameserver /etc/resolv.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010690"
echo "grep -i path= /home/*/.*"
grep -i path= /home/*/.*
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010700"
echo "find /boot -xdev -type d -perm -0002 -uid +999 -print"
find /boot -xdev -type d -perm -0002 -uid +999 -print
echo "find /home -xdev -type d -perm -0002 -uid +999 -print"
find /home -xdev -type d -perm -0002 -uid +999 -print
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010710"
echo "find /boot -xdev -type d -perm -0002 -gid +999 -print"
find /boot -xdev -type d -perm -0002 -gid +999 -print
echo "find /home -xdev -type d -perm -0002 -gid +999 -print"
find /home -xdev -type d -perm -0002 -gid +999 -print
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010720"
echo "pwck -r"
pwck -r
echo "awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1, $3, $6}' /etc/passwd"
awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1, $3, $6}' /etc/passwd
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010730"
echo "ls -ld $(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $6}' /etc/passwd)"
ls -ld $(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $6}' /etc/passwd)
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010740"
echo "ls -ld $(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $6}' /etc/passwd)"
ls -ld $(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $6}' /etc/passwd)
echo "grep $(grep user /etc/passwd | awk -F: '{print $4}') /etc/group"
grep $(grep user /etc/passwd | awk -F: '{print $4}') /etc/group
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010750"
echo "ls -ld $(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $6}' /etc/passwd)"
ls -ld $(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $6}' /etc/passwd)
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010760"
echo "grep -i create_home /etc/login.defs"
grep -i create_home /etc/login.defs
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010770"
echo "ls -al /home/directory.[^.]* | more"
ls -al /home/directory.[^.]* | more
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010780"
echo "find / -fstype xfs -nouser"
find / -fstype xfs -nouser
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010790"
echo "find / -fstype xfs -nogroup"
find / -fstype xfs -nogroup
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010800"
echo "awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1,$3,$6}' /etc/passwd"
awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1,$3,$6}' /etc/passwd
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010820"
echo "grep -i automaticloginenable /etc/gdm/custom.conf"
grep -i automaticloginenable /etc/gdm/custom.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010830"
echo "grep -ir PermitUserEnvironment /etc/ssh/sshd_config*"
grep -ir PermitUserEnvironment /etc/ssh/sshd_config*
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020010, RHEL-08-020012, RHEL-08-020014, RHEL-08-020016, RHEL-08-020018, RHEL-08-020020"
echo "RHEL-08-020022"
echo "grep pam_faillock.so /etc/pam.d/password-auth"
grep pam_faillock.so /etc/pam.d/password-auth
echo "grep pam_faillock.so /etc/pam.d/system-auth"
grep pam_faillock.so /etc/pam.d/system-auth
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020011"
echo "grep 'deny =' /etc/security/faillock.conf"
grep 'deny =' /etc/security/faillock.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020013"
echo "grep 'fail_interval =' /etc/security/faillock.conf"
grep 'fail_interval =' /etc/security/faillock.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020015"
echo "grep 'unlock_time =' /etc/security/faillock.conf"
grep 'unlock_time =' /etc/security/faillock.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020017"
echo "grep 'dir =' /etc/security/faillock.conf"
grep 'dir =' /etc/security/faillock.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020019"
echo "grep silent /etc/security/faillock.conf"
grep silent /etc/security/faillock.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020021"
echo "grep audit /etc/security/faillock.conf"
grep audit /etc/security/faillock.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020023"
echo "grep even_deny_root /etc/security/faillock.conf"
grep even_deny_root /etc/security/faillock.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020024"
echo "grep -r -s '^[^#].*maxlogins' /etc/security/limits.conf /etc/security/limits.d/*.conf"
grep -r -s '^[^#].*maxlogins' /etc/security/limits.conf /etc/security/limits.d/*.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020030"
echo "gsettings get org.gnome.desktop.screensaver lock-enabled"
gsettings get org.gnome.desktop.screensaver lock-enabled
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020040"
echo "grep -Ei 'lock-command|lock-session' /etc/tmux.conf"
grep -Ei 'lock-command|lock-session' /etc/tmux.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020041"
echo "ps all | grep tmux | grep -v grep"
ps all | grep tmux | grep -v grep
echo "grep -r tmux /etc/bashrc /etc/profile.d"
grep -r tmux /etc/bashrc /etc/profile.d
echo "cat /etc/profile.d/tmux.sh"
cat /etc/profile.d/tmux.sh
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020042"
echo "grep -i tmux /etc/shells"
grep -i tmux /etc/shells
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020050"
echo "grep -R removal-action /etc/dconf/db/*"
grep -R removal-action /etc/dconf/db/*
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020060"
echo "gsettings get org.gnome.desktop.session idle-delay"
gsettings get org.gnome.desktop.session idle-delay
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020070"
echo "grep -i lock-after-time /etc/tmux.conf"
grep -i lock-after-time /etc/tmux.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020080"
echo "grep system-db /etc/dconf/profile/user"
grep system-db /etc/dconf/profile/user
echo "grep -i lock-delay /etc/dconf/db/local.d/locks/*"
grep -i lock-delay /etc/dconf/db/local.d/locks/*
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020090"
echo "cat /etc/sssd/sssd.conf"
cat /etc/sssd/sssd.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020100"
echo "cat /etc/pam.d/password-auth | grep pam_pwquality"
cat /etc/pam.d/password-auth | grep pam_pwquality
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020110"
echo "grep -r ucredit /etc/security/pwquality.conf*"
grep -r ucredit /etc/security/pwquality.conf*
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020120"
echo "grep -r lcredit /etc/security/pwquality.conf*"
grep -r lcredit /etc/security/pwquality.conf*
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020130"
echo "grep -r dcredit /etc/security/pwquality.conf*"
grep -r dcredit /etc/security/pwquality.conf*
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020140"
echo "grep -r maxclassrepeat /etc/security/pwquality.conf*"
grep -r maxclassrepeat /etc/security/pwquality.conf*
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020150"
echo "grep -r maxrepeat /etc/security/pwquality.conf*"
grep -r maxrepeat /etc/security/pwquality.conf*
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020160"
echo "grep -r minclass /etc/security/pwquality.conf*"
grep -r minclass /etc/security/pwquality.conf*
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020170"
echo "grep -r difok /etc/security/pwquality.conf*"
grep -r difok /etc/security/pwquality.conf*
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020180"
awk -F: '$4 < 1 {print $1 " " $4}' /etc/shadow
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020190"
echo "grep -i pass_min_days /etc/login.defs"
grep -i pass_min_days /etc/login.defs
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020200"
echo "grep -i pass_max_days /etc/login.defs"
grep -i pass_max_days /etc/login.defs
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020210"
awk -F: '$5 > 60 {print $1 " " $5}' /etc/shadow
awk -F: '$5 <= 0 {print $1 " " $5}' /etc/shadow
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020220"
echo "grep -i remember /etc/pam.d/password-auth"
grep -i remember /etc/pam.d/password-auth
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020230"
echo "grep -r minlen /etc/security/pwquality.conf*"
grep -r minlen /etc/security/pwquality.conf*
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020231"
echo "grep -i  pass_min_len /etc/login.defs"
grep -i  pass_min_len /etc/login.defs
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020240"
awk -F ":" 'list[$3]++{print $1, $3}' /etc/passwd
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020250"
echo "grep cert_auth /etc/sssd/sssd.conf /etc/pam.d/*"
grep cert_auth /etc/sssd/sssd.conf /etc/pam.d/*
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020260"
echo "grep -i inactive /etc/default/useradd"
grep -i inactive /etc/default/useradd
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020280"
echo "grep -r ocredit /etc/security/pwquality.conf*"
grep -r ocredit /etc/security/pwquality.conf*
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020290"
echo "grep cache_credentials /etc/sssd/sssd.conf"
grep cache_credentials /etc/sssd/sssd.conf
echo "grep offline_credentials_expiration  /etc/sssd/sssd.conf"
grep offline_credentials_expiration  /etc/sssd/sssd.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020300"
echo "grep -r dictcheck /etc/security/pwquality.conf*"
grep -r dictcheck /etc/security/pwquality.conf*
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020310"
echo "grep -i fail_delay /etc/login.defs"
grep -i fail_delay /etc/login.defs
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020320"
echo "more /etc/passwd"
more /etc/passwd
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020330"
echo "grep -ir permitemptypasswords /etc/ssh/sshd_config*"
grep -ir permitemptypasswords /etc/ssh/sshd_config*
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020340"
echo "grep pam_lastlog /etc/pam.d/postlogin"
grep pam_lastlog /etc/pam.d/postlogin
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020350"
echo "grep -ir printlastlog /etc/ssh/sshd_config*"
grep -ir printlastlog /etc/ssh/sshd_config*
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020351"
echo "grep -i umask /etc/login.defs"
grep -i umask /etc/login.defs
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020352"
echo "grep -ir ^umask /home | grep -v '.bash_history'"
grep -ir ^umask /home | grep -v '.bash_history'
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020353"
echo "grep -i umask /etc/bashrc /etc/csh.cshrc /etc/profile"
grep -i umask /etc/bashrc /etc/csh.cshrc /etc/profile/user
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030000"
echo "grep execve /etc/audit/audit.rules"
grep execve /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030010"
echo "grep -s cron /etc/rsyslog.conf /etc/rsyslog.d/*.conf"
grep -s cron /etc/rsyslog.conf /etc/rsyslog.d/*.conf
echo "grep -s /var/log/messages /etc/rsyslog.conf /etc/rsyslog.d/*.conf"
grep -s /var/log/messages /etc/rsyslog.conf /etc/rsyslog.d/*.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030020"
echo "grep action_mail_acct /etc/audit/auditd.conf"
grep action_mail_acct /etc/audit/auditd.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030030"
echo 'grep "postmaster:\s*root$" /etc/aliases'
grep "postmaster:\s*root$" /etc/aliases
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030040"
echo "grep disk_error_action /etc/audit/auditd.conf"
grep disk_error_action /etc/audit/auditd.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030060"
echo "grep disk_full_action /etc/audit/auditd.conf"
grep disk_full_action /etc/audit/auditd.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030061"
echo "grep local_events /etc/audit/auditd.conf"
grep local_events /etc/audit/auditd.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030062"
echo 'grep "name_format" /etc/audit/auditd.conf'
grep "name_format" /etc/audit/auditd.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030063"
echo 'grep "log_format" /etc/audit/auditd.conf'
grep "log_format" /etc/audit/auditd.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030070, RHEL-08-030120"
echo "grep -iw log_file /etc/audit/auditd.conf"
grep -iw log_file /etc/audit/auditd.conf
echo 'stat -c "%a %n" /var/log/audit/audit.log'
stat -c "%a %n" /var/log/audit/audit.log
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030080, RHEL-08-030090"
echo "grep -iw log_file /etc/audit/auditd.conf"
grep -iw log_file /etc/audit/auditd.conf
echo "ls -al /var/log/audit/audit.log"
ls -al /var/log/audit/audit.log
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030100, RHEL-08-030110"
echo "grep -iw log_file /etc/audit/auditd.conf"
grep -iw log_file /etc/audit/auditd.conf
echo "ls -ld /var/log/audit"
ls -ld /var/log/audit
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030121"
echo 'grep "^\s*[^#]" /etc/audit/audit.rules | tail -1'
grep "^\s*[^#]" /etc/audit/audit.rules | tail -1
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030122"
echo "grep -i immutable /etc/audit/audit.rules"
grep -i immutable /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030130"
echo "grep /etc/shadow /etc/audit/audit.rules"
grep /etc/shadow /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030140"
echo "grep /etc/security/opasswd /etc/audit/audit.rules"
grep /etc/security/opasswd /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030150"
echo "grep /etc/passwd /etc/audit/audit.rules"
grep /etc/passwd /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030160"
echo "grep /etc/gshadow /etc/audit/audit.rules"
grep /etc/gshadow /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030170"
echo "grep /etc/group /etc/audit/audit.rules"
grep /etc/group /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030171"
echo "grep /etc/sudoers /etc/audit/audit.rules"
grep /etc/sudoers /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030172"
echo "grep /etc/sudoers.d/ /etc/audit/audit.rules"
grep /etc/sudoers.d/ /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030180"
echo "yum list installed audit"
yum list installed audit
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030190"
echo "grep -w /usr/bin/su /etc/audit/audit.rules"
grep -w /usr/bin/su /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030200"
echo "grep xattr /etc/audit/audit.rules"
grep xattr /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030250"
echo "grep -w chage /etc/audit/audit.rules"
grep -w chage /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030260"
echo "grep -w chcon /etc/audit/audit.rules"
grep -w chcon /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030280"
echo "grep ssh-agent /etc/audit/audit.rules"
grep ssh-agent /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030290"
echo "grep -w passwd /etc/audit/audit.rules"
grep -w passwd /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030300"
echo "grep -w /usr/bin/mount /etc/audit/audit.rules"
grep -w /usr/bin/mount /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030301"
echo "grep -w /usr/bin/umount /etc/audit/audit.rules"
grep -w /usr/bin/umount /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030302"
echo 'grep -w "\-S mount" /etc/audit/audit.rules'
grep -w "\-S mount" /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030310"
echo 'grep -w "unix_update" /etc/audit/audit.rules'
grep -w "unix_update" /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030311"
echo 'grep -w "postdrop" /etc/audit/audit.rules'
grep -w "postdrop" /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030312"
echo 'grep -w "postqueue" /etc/audit/audit.rules'
grep -w "postqueue" /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030313"
echo 'grep -w "semanage" /etc/audit/audit.rules'
grep -w "semanage" /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030314"
echo 'grep -w "setfiles" /etc/audit/audit.rules'
grep -w "setfiles" /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030315"
echo 'grep -w "userhelper" /etc/audit/audit.rules'
grep -w "userhelper" /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030316"
echo 'grep -w "setsebool" /etc/audit/audit.rules'
grep -w "setsebool" /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030317"
echo 'grep -w "unix_chkpwd" /etc/audit/audit.rules'
grep -w "unix_chkpwd" /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030320"
echo "grep ssh-keysign /etc/audit/audit.rules"
grep ssh-keysign /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030330"
echo "grep -w setfacl /etc/audit/audit.rules"
grep -w setfacl /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030340"
echo "grep -w pam_timestamp_check /etc/audit/audit.rules"
grep -w pam_timestamp_check /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030350"
echo "grep -w newgrp /etc/audit/audit.rules"
grep -w newgrp /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030360"
echo "grep init_module /etc/audit/audit.rules"
grep init_module /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030361"
echo "grep 'rename\|unlink\|rmdir' /etc/audit/audit.rules"
grep 'rename\|unlink\|rmdir' /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030370"
echo "grep -w gpasswd /etc/audit/audit.rules"
grep -w gpasswd /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030390"
echo 'grep -w "delete_module" /etc/audit/audit.rules'
grep -w "delete_module" /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030400"
echo "grep -w crontab /etc/audit/audit.rules"
grep -w crontab /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030410"
echo "grep -w chsh /etc/audit/audit.rules"
grep -w chsh /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030420"
echo "grep 'open\|truncate\|creat' /etc/audit/audit.rules"
grep 'open\|truncate\|creat' /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030480"
echo "grep chown /etc/audit/audit.rules"
grep chown /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030490"
echo "grep chmod /etc/audit/audit.rules"
grep chmod /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030550"
echo "grep -w sudo /etc/audit/audit.rules"
grep -w sudo /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030560"
echo "grep -w usermod /etc/audit/audit.rules"
grep -w usermod /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030570"
echo "grep -w chacl /etc/audit/audit.rules"
grep -w chacl /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030580"
echo 'grep "/usr/bin/kmod" /etc/audit/audit.rules'
grep "/usr/bin/kmod" /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030590"
echo "grep dir /etc/security/faillock.conf"
grep dir /etc/security/faillock.conf
echo "grep -w faillock /etc/audit/audit.rules"
grep -w faillock /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030600"
echo "grep -w lastlog /etc/audit/audit.rules"
grep -w lastlog /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030601, RHEL-08-030602"
echo "grub2-editenv list | grep audit"
grub2-editenv list | grep audit
echo "grep audit /etc/default/grub"
grep audit /etc/default/grub
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030603"
echo "grep -i auditbackend /etc/usbguard/usbguard-daemon.conf"
grep -i auditbackend /etc/usbguard/usbguard-daemon.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030610"
echo "ls -al /etc/audit/rules.d/*.rules"
ls -al /etc/audit/rules.d/*.rules
echo "ls -l /etc/audit/auditd.conf"
ls -l /etc/audit/auditd.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030620"
echo 'stat -c "%a %n" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/rsyslogd /sbin/augenrules'
stat -c "%a %n" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/rsyslogd /sbin/augenrules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030630"
echo 'stat -c "%U %n" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/rsyslogd /sbin/augenrules'
stat -c "%U %n" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/rsyslogd /sbin/augenrules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030640"
echo 'stat -c "%G %n" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/rsyslogd /sbin/augenrules'
stat -c "%G %n" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/rsyslogd /sbin/augenrules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030650"
echo "grep -E '(\/usr\/sbin\/(audit|au|rsys))' /etc/aide.conf"
grep -E '(\/usr\/sbin\/(audit|au|rsys))' /etc/aide.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030660"
echo "grep -iw log_file /etc/audit/auditd.conf"
grep -iw log_file /etc/audit/auditd.conf
echo "df -h /var/log/audit/"
df -h /var/log/audit/
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030670"
echo "yum list installed rsyslog"
yum list installed rsyslog
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030680"
echo "yum list installed rsyslog-gnutls"
yum list installed rsyslog-gnutls
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030690"
echo "grep @@ /etc/rsyslog.conf /etc/rsyslog.d/*.conf"
grep @@ /etc/rsyslog.conf /etc/rsyslog.d/*.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030700"
echo "grep -i overflow_action /etc/audit/auditd.conf"
grep -i overflow_action /etc/audit/auditd.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030710"
echo "grep -i '$DefaultNetstreamDriver' /etc/rsyslog.conf /etc/rsyslog.d/*.conf"
grep -i '$DefaultNetstreamDriver' /etc/rsyslog.conf /etc/rsyslog.d/*.conf
echo "grep -i '$ActionSendStreamDriverMode' /etc/rsyslog.conf /etc/rsyslog.d/*.conf"
grep -i '$ActionSendStreamDriverMode' /etc/rsyslog.conf /etc/rsyslog.d/*.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030720"
echo "grep -i '$ActionSendStreamDriverAuthMode' /etc/rsyslog.conf /etc/rsyslog.d/*.conf"
grep -i '$ActionSendStreamDriverAuthMode' /etc/rsyslog.conf /etc/rsyslog.d/*.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030730"
echo "grep -w space_left /etc/audit/auditd.conf"
grep -w space_left /etc/audit/auditd.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030740"
echo "grep maxpoll /etc/chrony.conf"
grep maxpoll /etc/chrony.conf
echo "grep -i server /etc/chrony.conf"
grep -i server /etc/chrony.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030741"
echo "grep -w 'port' /etc/chrony.conf"
grep -w 'port' /etc/chrony.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030742"
echo "grep -w 'cmdport' /etc/chrony.conf"
grep -w 'cmdport' /etc/chrony.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040000"
echo "yum list installed telnet-server"
yum list installed telnet-server
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040001"
echo "yum list installed abrt*"
yum list installed abrt*
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040002"
echo "yum list installed sendmail"
yum list installed sendmail
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040004"
echo "grub2-editenv list | grep pti"
grub2-editenv list | grep pti
echo "grep pti /etc/default/grub"
grep pti /etc/default/grub
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040010"
echo "yum list installed rsh-server"
yum list installed rsh-server
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040020"
echo 'grep -r uvcvideo /etc/modprobe.d/* | grep "/bin/true"'
grep -r uvcvideo /etc/modprobe.d/* | grep "/bin/true"
echo 'grep -r uvcvideo /etc/modprobe.d/* | grep "blacklist"'
grep -r uvcvideo /etc/modprobe.d/* | grep "blacklist"
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040021"
echo 'grep -r atm /etc/modprobe.d/* | grep "/bin/true"'
grep -r atm /etc/modprobe.d/* | grep "/bin/true"
echo 'grep -r atm /etc/modprobe.d/* | grep "blacklist"'
grep -r atm /etc/modprobe.d/* | grep "blacklist"
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040022"
echo 'grep -r can /etc/modprobe.d/* | grep "/bin/true"'
grep -r can /etc/modprobe.d/* | grep "/bin/true"
echo 'grep -r can /etc/modprobe.d/* | grep "blacklist"'
grep -r can /etc/modprobe.d/* | grep "blacklist"
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040023"
echo 'grep -r sctp /etc/modprobe.d/* | grep "/bin/true"'
grep -r sctp /etc/modprobe.d/* | grep "/bin/true"
echo 'grep -r sctp /etc/modprobe.d/* | grep "blacklist"'
grep -r sctp /etc/modprobe.d/* | grep "blacklist"
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040024"
echo 'grep -r tipc /etc/modprobe.d/* | grep "/bin/true"'
grep -r tipc /etc/modprobe.d/* | grep "/bin/true"
echo 'grep -r tipc /etc/modprobe.d/* | grep "blacklist"'
grep -r tipc /etc/modprobe.d/* | grep "blacklist"
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040025"
echo 'grep -r cramfs /etc/modprobe.d/* | grep "/bin/true"'
grep -r cramfs /etc/modprobe.d/* | grep "/bin/true"
echo 'grep -r cramfs /etc/modprobe.d/* | grep "blacklist"'
grep -r cramfs /etc/modprobe.d/* | grep "blacklist"
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040026"
echo 'grep -r firewire-core /etc/modprobe.d/* | grep "/bin/true"'
grep -r firewire-core /etc/modprobe.d/* | grep "/bin/true"
echo 'grep -r firewire-core /etc/modprobe.d/* | grep "blacklist"'
grep -r firewire-core /etc/modprobe.d/* | grep "blacklist"
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040030"
echo "firewall-cmd --list-all-zones"
firewall-cmd --list-all-zones
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040070"
echo "systemctl status autofs"
systemctl status autofs
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040080"
echo 'grep -r usb-storage /etc/modprobe.d/* | grep -i "/bin/true"'
grep -r usb-storage /etc/modprobe.d/* | grep -i "/bin/true"
echo 'grep usb-storage /etc/modprobe.d/* | grep -i "blacklist"'
grep usb-storage /etc/modprobe.d/* | grep -i "blacklist"
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040090"
echo "firewall-cmd --state"
firewall-cmd --state
echo "firewall-cmd --get-active-zones"
firewall-cmd --get-active-zones
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040100"
echo "yum list installed firewalld"
yum list installed firewalld
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040110"
echo "nmcli device status"
nmcli device status
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040111"
echo "grep bluetooth /etc/modprobe.d/*"
grep bluetooth /etc/modprobe.d/*
echo 'grep -r bluetooth /etc/modprobe.d | grep -i "blacklist" | grep -v "^#" '
grep -r bluetooth /etc/modprobe.d | grep -i "blacklist" | grep -v "^#" 
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040120"
echo "mount | grep /dev/shm"
mount | grep /dev/shm
echo "cat /etc/fstab | grep /dev/shm"
cat /etc/fstab | grep /dev/shm
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040121, RHEL-08-040122"
echo "mount | grep /dev/shm"
mount | grep /dev/shm
echo "cat /etc/fstab | grep /dev/shm"
cat /etc/fstab | grep /dev/shm
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040123, RHEL-08-040124, RHEL-08-040125"
echo "mount | grep /tmp"
mount | grep /tmp
echo "cat /etc/fstab | grep /tmp"
cat /etc/fstab | grep /tmp
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040126, RHEL-08-040127, RHEL-08-040128"
echo "mount | grep /var/log"
mount | grep /var/log
echo "cat /etc/fstab | grep /var/log"
cat /etc/fstab | grep /var/log
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040129, RHEL-08-040130, RHEL-08-040131"
echo "mount | grep /var/log/audit"
mount | grep /var/log/audit
echo "cat /etc/fstab | grep /var/log/audit"
cat /etc/fstab | grep /var/log/audit
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040132, RHEL-08-040133, RHEL-08-040134"
echo "mount | grep /var/tmp"
mount | grep /var/tmp
echo "cat /etc/fstab | grep /var/tmp"
cat /etc/fstab | grep /var/tmp
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040135"
echo "yum list installed fapolicyd"
yum list installed fapolicyd
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040140"
echo "usbguard list-rules"
usbguard list-rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040150"
echo "grep -i firewallbackend /etc/firewalld/firewalld.conf"
grep -i firewallbackend /etc/firewalld/firewalld.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040160"
echo "systemctl status sshd"
systemctl status sshd
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040161"
echo "grep -ir RekeyLimit /etc/ssh/sshd_config*"
grep -ir RekeyLimit /etc/ssh/sshd_config*
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040170"
echo "systemctl status ctrl-alt-del.target"
systemctl status ctrl-alt-del.target
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040171"
echo "grep logout /etc/dconf/db/local.d/*"
grep logout /etc/dconf/db/local.d/*
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040172"
echo "grep -i ctrl /etc/systemd/system.conf"
grep -i ctrl /etc/systemd/system.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040180"
echo "systemctl status debug-shell.service"
systemctl status debug-shell.service
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040190"
echo "yum list installed tftp-server"
yum list installed tftp-server
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040200"
echo "awk -F: '$3 == 0 {print $1}' /etc/passwd"
awk -F: '$3 == 0 {print $1}' /etc/passwd
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040210"
echo "sysctl net.ipv6.conf.default.accept_redirects"
sysctl net.ipv6.conf.default.accept_redirects
echo "grep -r net.ipv6.conf.default.accept_redirects /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf "
grep -r net.ipv6.conf.default.accept_redirects /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf 
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040220"
echo "sysctl net.ipv4.conf.all.send_redirects"
sysctl net.ipv4.conf.all.send_redirects
echo "grep -r net.ipv4.conf.all.send_redirects /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf"
grep -r net.ipv4.conf.all.send_redirects /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf 
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040230"
echo "sysctl net.ipv4.icmp_echo_ignore_broadcasts"
sysctl net.ipv4.icmp_echo_ignore_broadcasts
echo "grep -r net.ipv4.icmp_echo_ignore_broadcasts /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf"
grep -r net.ipv4.icmp_echo_ignore_broadcasts /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf 
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040240"
echo "sysctl net.ipv6.conf.all.accept_source_route"
sysctl net.ipv6.conf.all.accept_source_route
echo "grep -r net.ipv6.conf.all.accept_source_route /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf "
grep -r net.ipv6.conf.all.accept_source_route /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf 
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040250"
echo "sysctl net.ipv6.conf.default.accept_source_route"
sysctl net.ipv6.conf.default.accept_source_route
echo "grep -r net.ipv6.conf.default.accept_source_route /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf"
grep -r net.ipv6.conf.default.accept_source_route /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040260"
echo "sysctl net.ipv6.conf.all.forwarding"
sysctl net.ipv6.conf.all.forwarding
echo "grep -r net.ipv6.conf.all.forwarding /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf"
grep -r net.ipv6.conf.all.forwarding /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040261"
echo "sysctl net.ipv6.conf.all.accept_ra"
sysctl net.ipv6.conf.all.accept_ra
echo "grep -r net.ipv6.conf.all.accept_ra /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf"
grep -r net.ipv6.conf.all.accept_ra /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040262"
echo "sysctl net.ipv6.conf.default.accept_ra"
sysctl net.ipv6.conf.default.accept_ra
echo "grep -r net.ipv6.conf.default.accept_ra /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf"
grep -r net.ipv6.conf.default.accept_ra /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040270"
echo "sysctl net.ipv4.conf.default.send_redirects"
sysctl net.ipv4.conf.default.send_redirects
echo "grep -r net.ipv4.conf.default.send_redirects /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf"
grep -r net.ipv4.conf.default.send_redirects /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040280"
echo "sysctl net.ipv6.conf.all.accept_redirects"
sysctl net.ipv6.conf.all.accept_redirects
echo "grep -r net.ipv6.conf.all.accept_redirects /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf"
grep -r net.ipv6.conf.all.accept_redirects /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040281"
echo "sysctl kernel.unprivileged_bpf_disabled"
sysctl kernel.unprivileged_bpf_disabled
echo "grep -r kernel.unprivileged_bpf_disabled /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf"
grep -r kernel.unprivileged_bpf_disabled /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040282"
echo "sysctl kernel.yama.ptrace_scope"
sysctl kernel.yama.ptrace_scope
echo "grep -r kernel.yama.ptrace_scope /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf"
grep -r kernel.yama.ptrace_scope /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040283"
echo "sysctl kernel.kptr_restrict"
sysctl kernel.kptr_restrict
echo "grep -r kernel.kptr_restrict /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf"
grep -r kernel.kptr_restrict /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040284"
echo "sysctl user.max_user_namespaces"
sysctl user.max_user_namespaces
echo "grep -r user.max_user_namespaces /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf"
grep -r user.max_user_namespaces /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040285"
echo "sysctl net.ipv4.conf.all.rp_filter"
sysctl net.ipv4.conf.all.rp_filter
echo "grep -r net.ipv4.conf.all.rp_filter /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf"
grep -r net.ipv4.conf.all.rp_filter /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040290"
echo "yum list installed postfix"
yum list installed postfix
echo "postconf -n smtpd_client_restrictions"
postconf -n smtpd_client_restrictions
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040300"
echo "find / -name aide.conf"
find / -name aide.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040310"
echo "grep -E "[+]?acl" /etc/aide.conf"
grep -E "[+]?acl" /etc/aide.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040320"
echo "rpm -qa | grep xorg | grep server"
rpm -qa | grep xorg | grep server
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040330"
echo "ip link | grep -i promisc"
ip link | grep -i promisc
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040340"
echo 'grep -ir x11forwarding /etc/ssh/sshd_config* | grep -v "^#"'
grep -ir x11forwarding /etc/ssh/sshd_config* | grep -v "^#"
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040341"
echo "grep -ir x11uselocalhost /etc/ssh/sshd_config*"
grep -ir x11uselocalhost /etc/ssh/sshd_config*
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040350"
echo "grep server_args /etc/xinetd.d/tftp"
grep server_args /etc/xinetd.d/tftp
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040360"
echo "yum list installed *ftpd*"
yum list installed *ftpd*
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040370"
echo "yum list installed gssproxy"
yum list installed gssproxy
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040380"
echo "yum list installed iprutils"
yum list installed iprutils
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040390"
echo "yum list installed tuned"
yum list installed tuned
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010163"
echo "yum list installed krb5-server"
yum list installed krb5-server
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010382"
echo "grep -iw 'ALL' /etc/sudoers /etc/sudoers.d/*"
grep -iw 'ALL' /etc/sudoers /etc/sudoers.d/*
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010383"
echo "grep -Eir '(rootpw|targetpw|runaspw)' /etc/sudoers /etc/sudoers.d* | grep -v '#'"
grep -Eir '(rootpw|targetpw|runaspw)' /etc/sudoers /etc/sudoers.d* | grep -v '#'
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010384"
echo "grep -ir 'timestamp_timeout' /etc/sudoers /etc/sudoers.d"
grep -ir 'timestamp_timeout' /etc/sudoers /etc/sudoers.d
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010049"
echo "grep banner-message-enable /etc/dconf/db/local.d/*"
grep banner-message-enable /etc/dconf/db/local.d/*
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010141"
echo 'grep -iw "superusers" /boot/efi/EFI/redhat/grub.cfg'
grep -iw "superusers" /boot/efi/EFI/redhat/grub.cfg
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010149"
echo 'grep -iw "superusers" /boot/grub2/grub.cfg'
grep -iw "superusers" /boot/grub2/grub.cfg
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010152"
echo "grep sulogin-shell /usr/lib/systemd/system/emergency.service"
grep sulogin-shell /usr/lib/systemd/system/emergency.service
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010159"
echo "grep password /etc/pam.d/system-auth | grep pam_unix"
grep password /etc/pam.d/system-auth | grep pam_unix
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010201"
echo "grep -ir clientaliveinterval /etc/ssh/sshd_config*"
grep -ir clientaliveinterval /etc/ssh/sshd_config*
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010287"
echo "grep CRYPTO_POLICY /etc/sysconfig/sshd"
grep CRYPTO_POLICY /etc/sysconfig/sshd
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010472"
echo "yum list installed rng-tools"
yum list installed rng-tools
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010522"
echo "grep -ir GSSAPIAuthentication  /etc/ssh/sshd_config*"
grep -ir GSSAPIAuthentication  /etc/ssh/sshd_config*
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010544"
echo "grep /var/tmp /etc/fstab"
grep /var/tmp /etc/fstab
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010572"
echo "mount | grep '\s/boot/efi\s'"
mount | grep '\s/boot/efi\s'
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010731"
echo "ls -lLR /home/directory"
ls -lLR /home/directory
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020025"
echo "grep pam_faillock.so /etc/pam.d/system-auth"
grep pam_faillock.so /etc/pam.d/system-auth
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020026"
echo "grep pam_faillock.so /etc/pam.d/password-auth"
grep pam_faillock.so /etc/pam.d/password-auth
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020031"
echo "gsettings get org.gnome.desktop.screensaver lock-delay"
gsettings get org.gnome.desktop.screensaver lock-delay
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020032"
echo "gsettings get org.gnome.login-screen disable-user-list"
gsettings get org.gnome.login-screen disable-user-list
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020039"
echo "yum list installed tmux"
yum list installed tmux
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020081"
echo "grep system-db /etc/dconf/profile/user"
grep system-db /etc/dconf/profile/user
echo "grep -i idle /etc/dconf/db/local.d/locks/*"
grep -i idle /etc/dconf/db/local.d/locks/*
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020082"
echo "grep system-db /etc/dconf/profile/user"
grep system-db /etc/dconf/profile/user
echo "grep -i lock-enabled /etc/dconf/db/local.d/locks/*"
grep -i lock-enabled /etc/dconf/db/local.d/locks/*
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020331"
echo "grep -i nullok /etc/pam.d/system-auth"
grep -i nullok /etc/pam.d/system-auth
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020332"
echo "grep -i nullok /etc/pam.d/password-auth"
grep -i nullok /etc/pam.d/password-auth
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030181"
echo "systemctl status auditd.service"
systemctl status auditd.service
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-030731"
echo "grep -w space_left_action /etc/audit/auditd.conf"
grep -w space_left_action /etc/audit/auditd.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040101"
echo "systemctl is-active firewalld"
systemctl is-active firewalld
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040136"
echo "systemctl status fapolicyd.service"
systemctl status fapolicyd.service
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040137"
echo "tail /etc/fapolicyd/compiled.rules"
tail /etc/fapolicyd/compiled.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040139"
echo "yum list installed usbguard"
yum list installed usbguard
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040141"
echo "systemctl status usbguard.service"
systemctl status usbguard.service
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040159"
echo "yum list installed openssh-server"
yum list installed openssh-server
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040209"
echo "sysctl net.ipv4.conf.default.accept_redirects"
sysctl net.ipv4.conf.default.accept_redirects
echo "grep -r net.ipv4.conf.default.accept_redirects /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf"
grep -r net.ipv4.conf.default.accept_redirects /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf 
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040239"
echo "sysctl net.ipv4.conf.all.accept_source_route"
sysctl net.ipv4.conf.all.accept_source_route
echo "grep -r net.ipv4.conf.all.accept_source_route /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf"
grep -r net.ipv4.conf.all.accept_source_route /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040249"
echo "sysctl net.ipv4.conf.default.accept_source_route"
sysctl net.ipv4.conf.default.accept_source_route
echo "grep -r net.ipv4.conf.default.accept_source_route /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf"
grep -r net.ipv4.conf.default.accept_source_route /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040279"
echo "sysctl net.ipv4.conf.all.accept_redirects"
sysctl net.ipv4.conf.all.accept_redirects
echo "grep -r net.ipv4.conf.all.accept_redirects /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf"
grep -r net.ipv4.conf.all.accept_redirects /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040286"
echo "sysctl net.core.bpf_jit_harden"
sysctl net.core.bpf_jit_harden
echo "grep -r net.core.bpf_jit_harden /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf"
grep -r net.core.bpf_jit_harden /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf 
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010001"
echo "Deviation per BARA"
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020027"
echo "grep -w dir /etc/security/faillock.conf"
grep -w dir /etc/security/faillock.conf
echo "ls -Zd /var/log/faillock"
ls -Zd /var/log/faillock
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020028"
echo "grep -w dir /etc/pam.d/password-auth"
grep -w dir /etc/pam.d/password-auth
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040259"
echo "sysctl net.ipv4.conf.all.forwarding"
sysctl net.ipv4.conf.all.forwarding
echo "grep -r net.ipv4.conf.all.forwarding /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf"
grep -r net.ipv4.conf.all.forwarding /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010121"
echo "awk -F: '!$2 {print $1}' /etc/shadow"
awk -F: '!$2 {print $1}' /etc/shadow
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010331"
find /lib /lib64 /usr/lib /usr/lib64 -perm /022 -type d -exec stat -c "%n %a" '{}' \;
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010341"
find /lib /lib64 /usr/lib /usr/lib64 ! -user root -type d -exec stat -c "%n %U" '{}' \;
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010351"
find /lib /lib64 /usr/lib /usr/lib64 ! -group root -type d -exec stat -c "%n %G" '{}' \;
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010359"
echo "rpm -q aide"
rpm -q aide
echo "/usr/sbin/aide --check"
/usr/sbin/aide --check
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010379"
echo "grep include /etc/sudoers"
grep include /etc/sudoers
echo "grep -r include /etc/sudoers.d"
grep -r include /etc/sudoers.d
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010385"
echo "grep pam_succeed_if /etc/pam.d/sudo"
grep pam_succeed_if /etc/pam.d/sudo
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020101, RHEL-08-020102, RHEL-08-020103"
echo "cat /etc/pam.d/system-auth | grep pam_pwquality"
cat /etc/pam.d/system-auth | grep pam_pwquality
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020104"
echo "grep -r retry /etc/security/pwquality.conf*"
grep -r retry /etc/security/pwquality.conf*
echo "grep pwquality /etc/pam.d/system-auth /etc/pam.d/password-auth | grep retry"
grep pwquality /etc/pam.d/system-auth /etc/pam.d/password-auth | grep retry
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020221"
echo "grep -i remember /etc/pam.d/system-auth"
grep -i remember /etc/pam.d/system-auth
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040321"
echo "systemctl get-default"
systemctl get-default
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040400"
echo "semanage login -l | more"
semanage login -l | more
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-040342"
echo "grep -i kexalgorithms /etc/crypto-policies/back-ends/opensshserver.config"
grep -i kexalgorithms /etc/crypto-policies/back-ends/opensshserver.config
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010019"
echo 'rpm -q --queryformat "%{SUMMARY}\n" gpg-pubkey | grep -i "red hat"'
rpm -q --queryformat "%{SUMMARY}\n" gpg-pubkey | grep -i "red hat"
echo "gpg -q --keyid-format short --with-fingerprint /etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release"
gpg -q --keyid-format short --with-fingerprint /etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-010358"
echo "yum list installed mailx"
yum list installed mailx
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-08-020035"
echo "grep -i ^StopIdleSessionSec /etc/systemd/logind.conf"
grep -i ^StopIdleSessionSec /etc/systemd/logind.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"
echo "Security Configuration Guide"
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "2.5.3 SecConfGuide: disable cups"
echo "systemctl status cups"
systemctl status cups
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "2.5 list active services"
echo "systemctl list-units | grep service"
systemctl list-units | grep service
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "3.1.2.1 SecConfGuide: gpgcheck = 1"
echo "cat /etc/yum.conf"
cat /etc/yum.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "4.1.2 Check whether the system-auth and password-auth files are already symbolic links pointing to system-auth-ac and password-auth-ac (this is the system default)"
echo "ls -l /etc/pam.d/{password,system}-auth"
ls -l /etc/pam.d/{password,system}-auth
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "4.2.6 This protection is turned on by default. It is controlled by the following options in the /usr/lib/sysctl.d/50-default.conf file"
echo "cat /usr/lib/sysctl.d/50-default.conf"
cat /usr/lib/sysctl.d/50-default.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "4.4.2 Use the ss utility to list open ports in the listening state."
echo "ss -tlw"
ss -tlw
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "4.5.7.2. Checking if unbound is Running"
echo "systemctl status unbound"
systemctl status unbound
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "4.5.7.5. Checking if the Dnssec-trigger Daemon is Running"
echo "systemctl status dnssec-triggerd"
systemctl status dnssec-triggerd
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "4.7. Using OpenSSL"
echo "openssl list-public-key-algorithms"
openssl list-public-key-algorithms
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "4.7.4 To list available symmetric encryption algorithms, execute the enc command with an unsupported option, such as -l"
echo "openssl enc -l"
openssl enc -l
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "5.6.6 List all allowed ports"
echo "firewall-cmd --list-ports"
firewall-cmd --list-ports
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"
echo "NIST Controls"
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "SC-28 Check for TPM Message"
echo "dmesg | grep -i tpm"
dmesg | grep -i tpm
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "IA-5(2) list all certificates"
echo "trust list --filter=certificates"
trust list --filter=certificates
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "CM-6,IA-5 Display BIOS Information"
echo "dmidecode -t bios"
dmidecode -t bios
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "CM-6,SC-23 Display System Information"
echo "dmidecode -t system"
dmidecode -t system
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "AU-10"
echo "cat /etc/issue"
cat /etc/issue
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "SI-23"
echo "cat /etc/*-release"
cat /etc/*-release
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "SI-23"
echo "cat /etc/lsb-release"
cat /etc/lsb-release
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "SI-7"
echo "cat /proc/version"
cat /proc/version
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "SI-7"
echo "uname -a"
uname -a
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "SI-7"
echo "uname -mrs"
uname -mrs
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "SI-7,CM-6"
echo "rpm -q kernel"
rpm -q kernel
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "AU-11"
echo "dmesg | grep Linux"
dmesg | grep Linux
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "AU-14"
echo "cat /etc/profile"
cat /etc/profile
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "CM-7(5), AU-14(1)"
echo "ps aux"
ps aux
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "AU-14(1)"
echo "ps -elf"
ps -elf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "CM-4"
echo "cat /etc/service"
cat /etc/service
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "AC-2(7)"
echo "ps aux | grep root"
ps aux | grep root
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "AC-2(7)"
echo "ps -elf | grep root"
ps -elf | grep root
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "CM-7"
echo "dpkg -l"
dpkg -l
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "CM-6"
echo "rpm -qa"
rpm -qa
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "AC-18"
echo "ifconfig"
ifconfig
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "AC-21"
echo "ip link"
ip link
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "CM-1, CM-6"
echo "ip addr"
ip addr
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "CM-1, CM-6"
echo "/sbin/ifconfig -a"
/sbin/ifconfig -a
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "AC-17(3)"
echo "cat /etc/network/interfaces"
cat /etc/network/interfaces
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "AC-17(3)"
echo "cat /etc/sysconfig/network"
cat /etc/sysconfig/network
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "CM-6"
echo "cat /etc/resolv.conf"
cat /etc/resolv.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "CM-6"
echo "cat /etc/sysconfig/network"
cat /etc/sysconfig/network
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "AC-17(3)"
echo "cat /etc/networks"
cat /etc/networks
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "AC-17(3)"
echo "iptables -L"
iptables -L
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "SI-23"
echo "hostname"
hostname
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "SI-23"
echo "dnsdomainname"
dnsdomainname
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "SI-6"
echo "lsof -i"
lsof -i
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "SI-4(22)"
echo "lsof -i :80"
lsof -i :80
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "SI-4(22)"
echo "netstat -antup"
netstat -antup
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "SI-4(22)"
echo "netstat -antpx"
netstat -antpx
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "SI-4(22)"
echo "netstat -tulpn"
netstat -tulpn
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "CM-7"
echo "chkconfig --list"
chkconfig --list
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "IA-5(1)"
echo "cat /etc/passwd"
cat /etc/passwd
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "AC-2(3),AC-2(7)"
echo "cat /etc/group"
cat /etc/group
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "IA-5(1)"
echo "cat /etc/shadow"
cat /etc/shadow  
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "AC-10"
echo "cat ~/.ssh/*"
cat ~/.ssh/*
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "MP-4"
echo "df -h"
df -h
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "CM-3(5)"
echo "cat /etc/fstab"
cat /etc/fstab
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "AC-2"
echo "List active users"
echo "ipa user-find"
ipa user-find
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "AC-2"
echo "List all stage users"
echo "ipa stageuser-find"
ipa stageuser-find
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "SC-23"
echo "Display settings for account"
echo "ulimit -a"
ulimit -a
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "CM-7, AC-3"
echo "View all policies for the system"
echo "getsebool -a"
getsebool -a
