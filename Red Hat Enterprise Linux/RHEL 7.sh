#!/bin/bash

echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"
echo "Security Technical Implementation Guide (STIG) RHEL 7 V3R12"
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010010"
for i in `rpm -Va | grep -E '^.{1}M|^.{5}U|^.{6}G' | cut -d " " -f 4,5`;do for j in `rpm -qf $i`;do rpm -ql $j --dump | cut -d " " -f 1,5,6,7 | grep $i;done;done
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010030"
echo "grep banner-message-enable /etc/dconf/db/local.d/*"
grep banner-message-enable /etc/dconf/db/local.d/*
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010040"
echo "grep banner-message-text /etc/dconf/db/local.d/*"
grep banner-message-text /etc/dconf/db/local.d/*
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010050"
echo "more /etc/issue"
more /etc/issue
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "Check gnome version/installation"
echo "gnome-shell --version"
gnome-shell --version
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010060"
echo "grep -ir lock-enabled /etc/dconf/db/local.d/ | grep -v locks"
grep -ir lock-enabled /etc/dconf/db/local.d/ | grep -v locks
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010061"
echo "grep system-db /etc/dconf/profile/user"
grep system-db /etc/dconf/profile/user
echo "grep enable-smartcard-authentication /etc/dconf/db/local.d/*"
grep enable-smartcard-authentication /etc/dconf/db/local.d/*
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010070"
echo "grep -i idle-delay /etc/dconf/db/local.d/*"
grep -i idle-delay /etc/dconf/db/local.d/*
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010081"
echo "grep -i lock-delay /etc/dconf/db/local.d/locks/*"
grep -i lock-delay /etc/dconf/db/local.d/locks/*
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010082"
echo "grep -i idle-delay /etc/dconf/db/local.d/locks/*"
grep -i idle-delay /etc/dconf/db/local.d/locks/*
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010100"
echo "grep -i idle-activation-enabled /etc/dconf/db/local.d/*"
grep -i idle-activation-enabled /etc/dconf/db/local.d/*
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010101"
echo "grep -i idle-activation-enabled /etc/dconf/db/local.d/locks/*"
grep -i idle-activation-enabled /etc/dconf/db/local.d/locks/*
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010110"
echo "grep -i lock-delay /etc/dconf/db/local.d/*"
grep -i lock-delay /etc/dconf/db/local.d/*
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010118"
echo "cat /etc/pam.d/passwd | grep -i substack | grep -i system-auth"
cat /etc/pam.d/passwd | grep -i substack | grep -i system-auth
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010119"
echo "cat /etc/pam.d/system-auth | grep pam_pwquality"
cat /etc/pam.d/system-auth | grep pam_pwquality
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010120"
echo "grep ucredit /etc/security/pwquality.conf"
grep ucredit /etc/security/pwquality.conf 
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010130"
echo "grep lcredit /etc/security/pwquality.conf"
grep lcredit /etc/security/pwquality.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010140"
echo "grep dcredit /etc/security/pwquality.conf"
grep dcredit /etc/security/pwquality.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010150"
echo "grep ocredit /etc/security/pwquality.conf"
grep ocredit /etc/security/pwquality.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010160"
echo "grep difok /etc/security/pwquality.conf"
grep difok /etc/security/pwquality.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010170"
echo "grep minclass /etc/security/pwquality.conf"
grep minclass /etc/security/pwquality.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010180"
echo "grep maxrepeat /etc/security/pwquality.conf"
grep maxrepeat /etc/security/pwquality.conf 
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010190"
echo "grep maxclassrepeat /etc/security/pwquality.conf"
grep maxclassrepeat /etc/security/pwquality.conf 
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010200"
echo "grep password /etc/pam.d/system-auth /etc/pam.d/password-auth"
grep password /etc/pam.d/system-auth /etc/pam.d/password-auth
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010210"
echo "grep -i encrypt /etc/login.defs"
grep -i encrypt /etc/login.defs
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010220"
echo "grep -i sha512 /etc/libuser.conf"
grep -i sha512 /etc/libuser.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010230"
echo "grep -i pass_min_days /etc/login.defs"
grep -i pass_min_days /etc/login.defs
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010240"
awk -F: '$4 < 1 {print $1 " " $4}' /etc/shadow
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010250"
echo "grep -i pass_max_days /etc/login.defs"
grep -i pass_max_days /etc/login.defs
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010260"
awk -F: '$5 > 60 {print $1 " " $5}' /etc/shadow
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010270"
echo "grep -i remember /etc/pam.d/system-auth /etc/pam.d/password-auth"
grep -i remember /etc/pam.d/system-auth /etc/pam.d/password-auth
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010280"
echo "grep minlen /etc/security/pwquality.conf"
grep minlen /etc/security/pwquality.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010290"
echo "grep nullok /etc/pam.d/system-auth /etc/pam.d/password-auth"
grep nullok /etc/pam.d/system-auth /etc/pam.d/password-auth
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010300"
echo "grep -i PermitEmptyPasswords /etc/ssh/sshd_config"
grep -i PermitEmptyPasswords /etc/ssh/sshd_config
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010310"
echo "grep -i inactive /etc/default/useradd"
grep -i inactive /etc/default/useradd
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010320"
echo "grep pam_faillock.so /etc/pam.d/password-auth"
grep pam_faillock.so /etc/pam.d/password-auth
echo "grep pam_faillock.so /etc/pam.d/system-auth"
grep pam_faillock.so /etc/pam.d/system-auth
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010330"
echo "grep pam_faillock.so /etc/pam.d/password-auth"
grep pam_faillock.so /etc/pam.d/password-auth
echo "grep pam_faillock.so /etc/pam.d/system-auth"
grep pam_faillock.so /etc/pam.d/system-auth
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010340"
echo "grep -ir nopasswd /etc/sudoers /etc/sudoers.d"
grep -ir nopasswd /etc/sudoers /etc/sudoers.d
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010350"
echo "grep -i authenticate /etc/sudoers /etc/sudoers.d/*"
grep -i authenticate /etc/sudoers /etc/sudoers.d/*
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010430"
echo "grep -i fail_delay /etc/login.defs"
grep -i fail_delay /etc/login.defs
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010440"
echo "grep -i automaticloginenable /etc/gdm/custom.conf"
grep -i automaticloginenable /etc/gdm/custom.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010450"
echo "grep -i timedloginenable /etc/gdm/custom.conf"
grep -i timedloginenable /etc/gdm/custom.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010460"
echo "grep -i permituserenvironment /etc/ssh/sshd_config"
grep -i permituserenvironment /etc/ssh/sshd_config
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010470"
echo "grep -i hostbasedauthentication /etc/ssh/sshd_config"
grep -i hostbasedauthentication /etc/ssh/sshd_config
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010481"
echo "grep -i execstart /usr/lib/systemd/system/rescue.service | grep -i sulogin"
grep -i execstart /usr/lib/systemd/system/rescue.service | grep -i sulogin
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010482"
echo "grep -iw grub2_password /boot/grub2/user.cfg"
grep -iw grub2_password /boot/grub2/user.cfg
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010491"
echo "grep -iw grub2_password /boot/efi/EFI/redhat/user.cfg"
grep -iw grub2_password /boot/efi/EFI/redhat/user.cfg
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010500"
echo 'authconfig --test | grep "pam_pkcs11 is enabled"'
authconfig --test | grep "pam_pkcs11 is enabled"
echo 'authconfig --test | grep "smartcard removal action"'
authconfig --test | grep "smartcard removal action"
echo 'authconfig --test | grep "smartcard module"'
authconfig --test | grep "smartcard module"
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-020000"
echo "yum list installed rsh-server"
yum list installed rsh-server
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-020010"
echo "yum list installed ypserv"
yum list installed ypserv
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-020020"
echo "semanage login -l | more"
semanage login -l | more
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-020030 & RHEL-07-020040"
echo "ls -al /etc/cron.* | grep aide"
ls -al /etc/cron.* | grep aide
echo "grep aide /etc/crontab /var/spool/cron/root"
grep aide /etc/crontab /var/spool/cron/root
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-020050"
echo "grep gpgcheck /etc/yum.conf"
grep gpgcheck /etc/yum.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-020060"
echo "grep localpkg_gpgcheck /etc/yum.conf"
grep localpkg_gpgcheck /etc/yum.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-020100"
echo 'grep -r usb-storage /etc/modprobe.d/* | grep -i "/bin/true" | grep -v "^#"'
grep -r usb-storage /etc/modprobe.d/* | grep -i "/bin/true" | grep -v "^#"
echo 'grep usb-storage /etc/modprobe.d/* | grep -i "blacklist" | grep -v "^#"'
grep usb-storage /etc/modprobe.d/* | grep -i "blacklist" | grep -v "^#"
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-020101"
echo 'grep -r dccp /etc/modprobe.d/* | grep -i "/bin/true" | grep -v "^#"'
grep -r dccp /etc/modprobe.d/* | grep -i "/bin/true" | grep -v "^#"
echo 'grep -i dccp /etc/modprobe.d/* | grep -i "blacklist" | grep -v "^#"'
grep -i dccp /etc/modprobe.d/* | grep -i "blacklist" | grep -v "^#"
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-020110"
echo "systemctl status autofs"
systemctl status autofs
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-020200"
echo "grep -i clean_requirements_on_remove /etc/yum.conf"
grep -i clean_requirements_on_remove /etc/yum.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-020210"
echo "getenforce"
getenforce
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-020220"
echo "sestatus"
sestatus
echo "SELINUXTYPE"
grep -i "selinuxtype" /etc/selinux/config | grep -v '^#'
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-020230"
echo "systemctl status ctrl-alt-del.target"
systemctl status ctrl-alt-del.target
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-020231"
echo "grep logout /etc/dconf/db/local.d/*"
grep logout /etc/dconf/db/local.d/*
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-020240"
echo "grep -i umask /etc/login.defs"
grep -i umask /etc/login.defs
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-020250"
echo "cat /etc/redhat-release"
cat /etc/redhat-release
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-020260"
echo "yum history list | more"
yum history list | more
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-020270"
echo "more /etc/passwd"
more /etc/passwd
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-020300"
echo "pwck -r"
pwck -r
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-020310"
echo "awk -F: '$3 == 0 {print $1}' /etc/passwd"
awk -F: '$3 == 0 {print $1}' /etc/passwd
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-020320"
echo "find / -fstype xfs -nouser"
find / -fstype xfs -nouser
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-020330"
echo "find / -fstype xfs -nogroup"
find / -fstype xfs -nogroup
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-020610"
echo "grep -i create_home /etc/login.defs"
grep -i create_home /etc/login.defs
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-020620"
echo "awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1, $3, $6}' /etc/passwd"
awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1, $3, $6}' /etc/passwd
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-020630"
echo "ls -ld $(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $6}' /etc/passwd)"
ls -ld $(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $6}' /etc/passwd)
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-020640"
echo "ls -ld $(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $6}' /etc/passwd)"
ls -ld $(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $6}' /etc/passwd)
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-020650"
echo "ls -ld $(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $6}' /etc/passwd)"
ls -ld $(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $6}' /etc/passwd)
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-020660, RHEL-07-020670, & RHEL-07-020680"
echo "ls -lLR /home/directory"
ls -lLR /home/directory
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-020690 & RHEL-07-020710"
echo "awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1, $3, $6}' /etc/passwd"
awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1, $3, $6}' /etc/passwd
echo "ls -al /home/directory.[^.]* | more"
ls -al /home/directory.[^.]* | more
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-020700"
echo "awk -F: '($4>=1000)&&($7 !~ /nologin/){print $1, $4, $6}' /etc/passwd"
awk -F: '($4>=1000)&&($7 !~ /nologin/){print $1, $4, $6}' /etc/passwd
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-020720"
echo "grep -i path= /home/directory/.*"
grep -i path= /home/directory/.*
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-020730"
echo "find / -xdev -perm -002 -type f -exec ls -ld {} \; | more"
find / -xdev -perm -002 -type f -exec ls -ld {} \; | more
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-020900"
echo 'find /dev -context *:device_t:* \( -type c -o -type b \) -printf "%p %Z\n"'
find /dev -context *:device_t:* \( -type c -o -type b \) -printf "%p %Z\n"
echo 'find /dev -context *:unlabeled_t:* \( -type c -o -type b \) -printf "%p %Z\n"'
find /dev -context *:unlabeled_t:* \( -type c -o -type b \) -printf "%p %Z\n"
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-021000 & RHEL-07-021010"
echo "awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1, $3, $6}' /etc/passwd"
awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1, $3, $6}' /etc/passwd
echo "more /etc/fstab"
more /etc/fstab
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-021020"
echo "more /etc/fstab | grep nfs"
more /etc/fstab | grep nfs
echo "mount | grep nfs | grep nosuid"
mount | grep nfs | grep nosuid
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-021021"
echo "mount | grep nfs | grep noexec"
mount | grep nfs | grep noexec
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-021024"
echo "cat /etc/fstab | grep /dev/shm"
cat /etc/fstab | grep /dev/shm
echo "mount | grep /dev/shm"
mount | grep /dev/shm
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-021030"
echo "find /boot -xdev -type d -perm -0002 -gid +999 -print"
find /boot -xdev -type d -perm -0002 -gid +999 -print
echo "find /home -xdev -type d -perm -0002 -gid +999 -print"
find /home -xdev -type d -perm -0002 -gid +999 -print
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-021040"
echo "grep -ir ^umask /home | grep -v '.bash_history'"
grep -ir ^umask /home | grep -v '.bash_history'
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-021100"
echo "grep cron /etc/rsyslog.conf  /etc/rsyslog.d/*.conf"
grep cron /etc/rsyslog.conf  /etc/rsyslog.d/*.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-021110 & RHEL-07-021120"
echo "ls -al /etc/cron.allow"
ls -al /etc/cron.allow
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-021300"
echo "systemctl status kdump.service"
systemctl status kdump.service
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-021310"
echo "awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1, $3, $6, $7}' /etc/passwd"
awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1, $3, $6, $7}' /etc/passwd
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-021320"
echo "grep /var /etc/fstab"
grep /var /etc/fstab
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-021330"
echo "grep /var/log/audit /etc/fstab"
grep /var/log/audit /etc/fstab
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-021340"
echo "grep -i /tmp /etc/fstab"
grep -i /tmp /etc/fstab
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-021350"
echo "yum list installed dracut-fips"
yum list installed dracut-fips
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-021600, RHEL-07-021610, & RHEL-07-021620"
echo "cat /etc/aide.conf"
cat /etc/aide.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "Manual AIDE Integrity Check"
echo "aide --check"
aide --check
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-021700"
echo "find / -name grub.cfg"
find / -name grub.cfg
echo "grep -cw menuentry /boot/grub2/grub.cfg"
grep -cw menuentry /boot/grub2/grub.cfg
echo "grep 'set root' /boot/grub2/grub.cfg"
grep 'set root' /boot/grub2/grub.cfg
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-021710"
echo "yum list installed telnet-server"
yum list installed telnet-server
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-030000"
echo "systemctl is-active auditd.service"
systemctl is-active auditd.service
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-030010"
echo 'auditctl -s | grep -i "fail"'
auditctl -s | grep -i "fail"
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-030201"
echo 'cat /etc/audisp/plugins.d/au-remote.conf | grep -v "^#"'
cat /etc/audisp/plugins.d/au-remote.conf | grep -v "^#"
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-030210"
echo 'grep "overflow_action" /etc/audisp/audispd.conf'
grep "overflow_action" /etc/audisp/audispd.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-030211"
echo 'grep "name_format" /etc/audisp/audispd.conf'
grep "name_format" /etc/audisp/audispd.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-030300"
echo "grep -i remote_server /etc/audisp/audisp-remote.conf"
grep -i remote_server /etc/audisp/audisp-remote.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-030310"
echo "grep -i enable_krb5 /etc/audisp/audisp-remote.conf"
grep -i enable_krb5 /etc/audisp/audisp-remote.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-030320"
echo "grep -i disk_full_action /etc/audisp/audisp-remote.conf"
grep -i disk_full_action /etc/audisp/audisp-remote.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-030321"
echo "grep -i network_failure_action /etc/audisp/audisp-remote.conf"
grep -i network_failure_action /etc/audisp/audisp-remote.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-030330"
echo "grep -iw log_file /etc/audit/auditd.conf"
grep -iw log_file /etc/audit/auditd.conf
echo "grep -iw space_left /etc/audit/auditd.conf"
grep -iw space_left /etc/audit/auditd.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-030340"
echo "grep -i space_left_action  /etc/audit/auditd.conf"
grep -i space_left_action  /etc/audit/auditd.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-030350"
echo "grep -i action_mail_acct  /etc/audit/auditd.conf"
grep -i action_mail_acct  /etc/audit/auditd.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-030360"
echo "grep -iw execve /etc/audit/audit.rules"
grep -iw execve /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-030370"
echo "grep chown /etc/audit/audit.rules"
grep chown /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-030410"
echo "grep chmod /etc/audit/audit.rules"
grep chmod /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-030440"
echo "grep xattr /etc/audit/audit.rules"
grep xattr /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-030510"
echo "grep 'open\|truncate\|creat' /etc/audit/audit.rules"
grep 'open\|truncate\|creat' /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-030560"
echo 'grep -w "/usr/sbin/semanage" /etc/audit/audit.rules'
grep -w "/usr/sbin/semanage" /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-030570"
echo 'grep -w "/usr/sbin/setsebool" /etc/audit/audit.rules'
grep -w "/usr/sbin/setsebool" /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-030580"
echo 'grep -w "/usr/bin/chcon" /etc/audit/audit.rules'
grep -w "/usr/bin/chcon" /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-030590"
echo 'grep -w "/usr/sbin/setfiles" /etc/audit/audit.rules'
grep -w "/usr/sbin/setfiles" /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-030610"
echo "grep -i /var/run/faillock /etc/audit/audit.rules"
grep -i /var/run/faillock /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-030620"
echo "grep -i /var/log/lastlog /etc/audit/audit.rules"
grep -i /var/log/lastlog /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-030630"
echo 'grep -w "/usr/bin/passwd" /etc/audit/audit.rules'
grep -w "/usr/bin/passwd" /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-030640"
echo 'grep -w "/usr/sbin/unix_chkpwd" /etc/audit/audit.rules'
grep -w "/usr/sbin/unix_chkpwd" /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-030650"
echo 'grep -w "/usr/bin/gpasswd" /etc/audit/audit.rules'
grep -w "/usr/bin/gpasswd" /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-030660"
echo 'grep -w "/usr/bin/chage" /etc/audit/audit.rules'
grep -w "/usr/bin/chage" /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-030670"
echo 'grep -w "/usr/sbin/userhelper" /etc/audit/audit.rules'
grep -w "/usr/sbin/userhelper" /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-030680"
echo 'grep -w "/usr/bin/su" /etc/audit/audit.rules'
grep -w "/usr/bin/su" /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-030690"
echo 'grep -w "/usr/bin/sudo" /etc/audit/audit.rules'
grep -w "/usr/bin/sudo" /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-030700"
echo 'grep -i "/etc/sudoers" /etc/audit/audit.rules'
grep -i "/etc/sudoers" /etc/audit/audit.rules
echo 'grep -i "/etc/sudoers.d/" /etc/audit/audit.rules'
grep -i "/etc/sudoers.d/" /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-030710"
echo 'grep -w "/usr/bin/newgrp" /etc/audit/audit.rules'
grep -w "/usr/bin/newgrp" /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-030720"
echo 'grep -w "/usr/bin/chsh" /etc/audit/audit.rules'
grep -w "/usr/bin/chsh" /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-030740"
echo 'grep -w "mount" /etc/audit/audit.rules'
grep -w "mount" /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-030750"
echo 'grep -w "/usr/bin/umount" /etc/audit/audit.rules'
grep -w "/usr/bin/umount" /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-030760"
echo 'grep -w "/usr/sbin/postdrop" /etc/audit/audit.rules'
grep -w "/usr/sbin/postdrop" /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-030770"
echo 'grep -w "/usr/sbin/postqueue" /etc/audit/audit.rules'
grep -w "/usr/sbin/postqueue" /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-030780"
echo 'grep -w "/usr/libexec/openssh/ssh-keysign" /etc/audit/audit.rules'
grep -w "/usr/libexec/openssh/ssh-keysign" /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-030800"
echo 'grep -w "/usr/bin/crontab" /etc/audit/audit.rules'
grep -w "/usr/bin/crontab" /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-030810"
echo 'grep -w "/usr/sbin/pam_timestamp_check" /etc/audit/audit.rules'
grep -w "/usr/sbin/pam_timestamp_check" /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-030819"
echo 'grep -w "create_module" /etc/audit/audit.rules'
grep -w "create_module" /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-030820"
echo "grep init_module /etc/audit/audit.rules "
grep init_module /etc/audit/audit.rules 
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-030830"
echo 'grep -w "delete_module" /etc/audit/audit.rules'
grep -w "delete_module" /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-030840"
echo 'grep "/usr/bin/kmod" /etc/audit/audit.rules'
grep "/usr/bin/kmod" /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-030870"
echo "grep /etc/passwd /etc/audit/audit.rules"
grep /etc/passwd /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-030871"
echo "grep /etc/group /etc/audit/audit.rules"
grep /etc/group /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-030872"
echo "grep /etc/gshadow /etc/audit/audit.rules"
grep /etc/gshadow /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-030873"
echo "grep /etc/shadow /etc/audit/audit.rules"
grep /etc/shadow /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-030874"
echo "grep /etc/security/opasswd /etc/audit/audit.rules"
grep /etc/security/opasswd /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-030910"
echo "grep 'unlink\|rename\|rmdir' /etc/audit/audit.rules"
grep 'unlink\|rename\|rmdir' /etc/audit/audit.rules
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-031000"
echo "grep @ /etc/rsyslog.conf /etc/rsyslog.d/*.conf"
grep @ /etc/rsyslog.conf /etc/rsyslog.d/*.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-031010"
echo "grep imtcp /etc/rsyslog.conf"
grep imtcp /etc/rsyslog.conf
echo "grep imudp /etc/rsyslog.conf"
grep imudp /etc/rsyslog.conf
echo "grep imrelp /etc/rsyslog.conf"
grep imrelp /etc/rsyslog.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040000"
echo 'grep "maxlogins" /etc/security/limits.conf /etc/security/limits.d/*.conf'
grep "maxlogins" /etc/security/limits.conf /etc/security/limits.d/*.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040100"
echo "firewall-cmd --list-all"
firewall-cmd --list-all
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040110"
echo "grep -i ciphers /etc/ssh/sshd_config"
grep -i ciphers /etc/ssh/sshd_config
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040160"
echo "grep -irw tmout /etc/profile /etc/bashrc /etc/profile.d"
grep -irw tmout /etc/profile /etc/bashrc /etc/profile.d
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040170"
echo "grep -i banner /etc/ssh/sshd_config"
grep -i banner /etc/ssh/sshd_config
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040180"
echo "systemctl status sssd.service"
systemctl status sssd.service
echo 'grep -i "id_provider" /etc/sssd/sssd.conf'
grep -i "id_provider" /etc/sssd/sssd.conf
echo 'grep -i "start_tls" /etc/sssd/sssd.conf'
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040190"
echo "grep -i tls_reqcert /etc/sssd/sssd.conf"
grep -i tls_reqcert /etc/sssd/sssd.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040200"
echo "grep -i tls_cacert /etc/sssd/sssd.conf"
grep -i tls_cacert /etc/sssd/sssd.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040201"
echo "grep -r kernel.randomize_va_space /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* "
grep -r kernel.randomize_va_space /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* 
echo "/sbin/sysctl -a | grep kernel.randomize_va_space "
/sbin/sysctl -a | grep kernel.randomize_va_space 
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040300"
echo "yum list installed \*ssh\*"
yum list installed \*ssh\*
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040310"
echo "systemctl status sshd"
systemctl status sshd
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040320"
echo "grep -iw clientaliveinterval /etc/ssh/sshd_config"
grep -iw clientaliveinterval /etc/ssh/sshd_config
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040330"
echo "grep RhostsRSAAuthentication /etc/ssh/sshd_config"
grep RhostsRSAAuthentication /etc/ssh/sshd_config
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040340"
echo "grep -i clientalivecount /etc/ssh/sshd_config"
grep -i clientalivecount /etc/ssh/sshd_config
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040350"
echo "grep -i IgnoreRhosts /etc/ssh/sshd_config"
grep -i IgnoreRhosts /etc/ssh/sshd_config
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040360"
echo "grep -i printlastlog /etc/ssh/sshd_config"
grep -i printlastlog /etc/ssh/sshd_config
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040370"
echo "grep -i permitrootlogin /etc/ssh/sshd_config"
grep -i permitrootlogin /etc/ssh/sshd_config
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040380"
echo "grep -i IgnoreUserKnownHosts /etc/ssh/sshd_config"
grep -i IgnoreUserKnownHosts /etc/ssh/sshd_config
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040390"
echo "grep -i protocol /etc/ssh/sshd_config"
grep -i protocol /etc/ssh/sshd_config
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040400"
echo "grep -i macs /etc/ssh/sshd_config"
grep -i macs /etc/ssh/sshd_config
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040410"
echo "find /etc/ssh -name '*.pub' -exec ls -lL {} \;"
find /etc/ssh -name '*.pub' -exec ls -lL {} \;
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040420"
echo "find / -name '*ssh_host*key' | xargs ls -lL"
find / -name '*ssh_host*key' | xargs ls -lL
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040430"
echo "grep -i gssapiauth /etc/ssh/sshd_config"
grep -i gssapiauth /etc/ssh/sshd_config
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040440"
echo "grep -i kerberosauth /etc/ssh/sshd_config"
grep -i kerberosauth /etc/ssh/sshd_config
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040450"
echo "grep -i strictmodes /etc/ssh/sshd_config"
grep -i strictmodes /etc/ssh/sshd_config
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040460"
echo "grep -i usepriv /etc/ssh/sshd_config"
grep -i usepriv /etc/ssh/sshd_config
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040470"
echo "grep -i compression /etc/ssh/sshd_config"
grep -i compression /etc/ssh/sshd_config
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040500"
echo "ps -ef | grep ntp"
ps -ef | grep ntp
echo "ps -ef | grep chronyd"
ps -ef | grep chronyd
echo "grep maxpoll /etc/ntp.conf"
grep maxpoll /etc/ntp.conf
echo 'grep -i "ntpd -q" /etc/cron.daily/*'
grep -i "ntpd -q" /etc/cron.daily/*
echo "ls -al /etc/cron.* | grep ntp"
ls -al /etc/cron.* | grep ntp
echo "grep maxpoll /etc/chrony.conf"
grep maxpoll /etc/chrony.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040520"
echo "yum list installed firewalld"
yum list installed firewalld
echo "systemctl status firewalld"
systemctl status firewalld
echo "firewall-cmd --state"
firewall-cmd --state
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040530"
echo "grep pam_lastlog /etc/pam.d/postlogin"
grep pam_lastlog /etc/pam.d/postlogin
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040540"
echo "find / -name '*.shosts'"
find / -name '*.shosts'
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040550"
echo "find / -name shosts.equiv"
find / -name shosts.equiv
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040600"
echo "grep hosts /etc/nsswitch.conf"
grep hosts /etc/nsswitch.conf
echo "ls -al /etc/resolv.conf"
ls -al /etc/resolv.conf
echo "grep nameserver /etc/resolv.conf"
grep nameserver /etc/resolv.conf
echo "lsattr /etc/resolv.conf"
lsattr /etc/resolv.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040610"
echo "grep -r net.ipv4.conf.all.accept_source_route /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null"
grep -r net.ipv4.conf.all.accept_source_route /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null
echo "/sbin/sysctl -a | grep net.ipv4.conf.all.accept_source_route"
/sbin/sysctl -a | grep net.ipv4.conf.all.accept_source_route
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040611"
echo "grep -r net.ipv4.conf.all.rp_filter /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null"
grep -r net.ipv4.conf.all.rp_filter /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null
echo "/sbin/sysctl -a | grep net.ipv4.conf.all.rp_filter"
/sbin/sysctl -a | grep net.ipv4.conf.all.rp_filter
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040612"
echo "grep -r net.ipv4.conf.default.rp_filter /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null"
grep -r net.ipv4.conf.default.rp_filter /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null
echo "/sbin/sysctl -a | grep net.ipv4.conf.default.rp_filter"
/sbin/sysctl -a | grep net.ipv4.conf.default.rp_filter
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040620"
echo "grep -r net.ipv4.conf.default.accept_source_route /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null"
grep -r net.ipv4.conf.default.accept_source_route /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null
echo "/sbin/sysctl -a | grep net.ipv4.conf.default.accept_source_route"
/sbin/sysctl -a | grep net.ipv4.conf.default.accept_source_route
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040630"
echo "grep -r net.ipv4.icmp_echo_ignore_broadcasts /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null"
grep -r net.ipv4.icmp_echo_ignore_broadcasts /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null
echo "/sbin/sysctl -a | grep net.ipv4.icmp_echo_ignore_broadcasts"
/sbin/sysctl -a | grep net.ipv4.icmp_echo_ignore_broadcasts
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040640"
echo "grep -r net.ipv4.conf.default.accept_redirects /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null"
grep -r net.ipv4.conf.default.accept_redirects /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null
echo "/sbin/sysctl -a | grep net.ipv4.conf.default.accept_redirects"
/sbin/sysctl -a | grep net.ipv4.conf.default.accept_redirects
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040641"
echo "grep -r net.ipv4.conf.all.accept_redirects /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null"
grep -r net.ipv4.conf.all.accept_redirects /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null
echo "/sbin/sysctl -a | grep net.ipv4.conf.all.accept_redirects"
/sbin/sysctl -a | grep net.ipv4.conf.all.accept_redirects
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040650"
echo "grep -r net.ipv4.conf.default.send_redirects /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null"
grep -r net.ipv4.conf.default.send_redirects /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null
echo "/sbin/sysctl -a | grep net.ipv4.conf.default.send_redirects"
/sbin/sysctl -a | grep net.ipv4.conf.default.send_redirects
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040660"
echo "grep -r net.ipv4.conf.all.send_redirects /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null"
grep -r net.ipv4.conf.all.send_redirects /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null
echo "/sbin/sysctl -a | grep net.ipv4.conf.all.send_redirects"
/sbin/sysctl -a | grep net.ipv4.conf.all.send_redirects
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040670"
echo "ip link | grep -i promisc"
ip link | grep -i promisc
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040680"
echo "yum list installed postfix"
yum list installed postfix
echo "postconf -n smtpd_client_restrictions"
postconf -n smtpd_client_restrictions
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040690"
echo "yum list installed vsftpd"
yum list installed vsftpd
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040700"
echo "yum list installed tftp-server"
yum list installed tftp-server
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040710"
echo 'grep -i x11forwarding /etc/ssh/sshd_config | grep -v "^#"'
grep -i x11forwarding /etc/ssh/sshd_config | grep -v "^#"
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040720"
echo "grep server_args /etc/xinetd.d/tftp"
grep server_args /etc/xinetd.d/tftp
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040730"
echo "systemctl get-default"
systemctl get-default
echo "rpm -qa | grep xorg | grep server"
rpm -qa | grep xorg | grep server
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040740"
echo "grep -r net.ipv4.ip_forward /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null"
grep -r net.ipv4.ip_forward /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null
echo "/sbin/sysctl -a | grep net.ipv4.ip_forward"
/sbin/sysctl -a | grep net.ipv4.ip_forward
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040750"
echo "cat /etc/fstab | grep nfs"
cat /etc/fstab | grep nfs
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040800"
echo "ls -al /etc/snmp/snmpd.conf"
ls -al /etc/snmp/snmpd.conf
echo "grep public /etc/snmp/snmpd.conf"
grep public /etc/snmp/snmpd.conf
echo "grep private /etc/snmp/snmpd.conf"
grep private /etc/snmp/snmpd.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040810"
echo "firewall-cmd --get-default-zone"
firewall-cmd --get-default-zone
echo "firewall-cmd --list-all --zone=public"
firewall-cmd --list-all --zone=public
echo "ls -al /etc/hosts.allow"
ls -al /etc/hosts.allow
echo "ls -al /etc/hosts.deny"
ls -al /etc/hosts.deny
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040820"
echo "yum list installed libreswan"
yum list installed libreswan
echo "systemctl status ipsec"
systemctl status ipsec
echo "grep -iw conn /etc/ipsec.conf /etc/ipsec.d/*.conf"
grep -iw conn /etc/ipsec.conf /etc/ipsec.d/*.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040830"
echo "grep -r net.ipv6.conf.all.accept_source_route /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null"
grep -r net.ipv6.conf.all.accept_source_route /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null
echo "/sbin/sysctl -a | grep net.ipv6.conf.all.accept_source_route"
/sbin/sysctl -a | grep net.ipv6.conf.all.accept_source_route
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-041001"
echo "yum list installed pam_pkcs11"
yum list installed pam_pkcs11
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-041002"
echo "grep services /etc/sssd/sssd.conf /etc/sssd/conf.d/*.conf"
grep services /etc/sssd/sssd.conf /etc/sssd/conf.d/*.conf
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-041003"
echo 'grep cert_policy /etc/pam_pkcs11/pam_pkcs11.conf | grep -v "^#"'
grep cert_policy /etc/pam_pkcs11/pam_pkcs11.conf | grep -v "^#"
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-041010"
echo "nmcli device"
nmcli device
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010020"
echo "rpm -Va --noconfig | grep '^..5'"
rpm -Va --noconfig | grep '^..5'
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-020019 & RHEL-07-032000"
echo "Deviation per BARA"
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010062"
echo "grep system-db /etc/dconf/profile/user"
grep system-db /etc/dconf/profile/user
echo "grep -i lock-enabled /etc/dconf/db/local.d/locks/*"
grep -i lock-enabled /etc/dconf/db/local.d/locks/*
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-020111"
echo "cat /etc/dconf/db/local.d/00-No-Automount"
cat /etc/dconf/db/local.d/00-No-Automount
echo "cat /etc/dconf/db/local.d/locks/00-No-Automount"
cat /etc/dconf/db/local.d/locks/00-No-Automount
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-021031"
echo "find /boot -xdev -type d -perm -0002 -uid +999 -print"
find /boot -xdev -type d -perm -0002 -uid +999 -print
echo "find /home -xdev -type d -perm -0002 -uid +999 -print"
find /home -xdev -type d -perm -0002 -uid +999 -print
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-910055"
echo "ls -la /var/log/audit"
ls -la /var/log/audit
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040711"
echo "grep -i x11uselocalhost /etc/ssh/sshd_config"
grep -i x11uselocalhost /etc/ssh/sshd_config
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010341"
echo "grep -iw 'ALL' /etc/sudoers /etc/sudoers.d/*"
grep -iw 'ALL' /etc/sudoers /etc/sudoers.d/*
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010342"
echo "grep -Eir '(rootpw|targetpw|runaspw)' /etc/sudoers /etc/sudoers.d* | grep -v '#'"
grep -Eir '(rootpw|targetpw|runaspw)' /etc/sudoers /etc/sudoers.d* | grep -v '#'
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010343"
echo "grep -ir 'timestamp_timeout' /etc/sudoers /etc/sudoers.d"
grep -ir 'timestamp_timeout' /etc/sudoers /etc/sudoers.d
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010483"
echo 'grep -iw "superusers" /boot/grub2/grub.cfg'
grep -iw "superusers" /boot/grub2/grub.cfg
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010492"
echo 'grep -iw "superusers" /boot/efi/EFI/redhat/grub.cfg'
grep -iw "superusers" /boot/efi/EFI/redhat/grub.cfg
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-020021"
echo "semanage user -l"
semanage user -l
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-020022"
echo "getsebool ssh_sysadm_login"
getsebool ssh_sysadm_login
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-020023"
echo "grep -r sysadm_r /etc/sudoers /etc/sudoers.d"
grep -r sysadm_r /etc/sudoers /etc/sudoers.d
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010291"
echo "awk -F: '!$2 {print $1}' /etc/shadow"
awk -F: '!$2 {print $1}' /etc/shadow
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010339"
echo "grep include /etc/sudoers"
grep include /etc/sudoers
echo "grep -r include /etc/sudoers.d"
grep -r include /etc/sudoers.d
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010344"
echo "grep pam_succeed_if /etc/pam.d/sudo"
grep pam_succeed_if /etc/pam.d/sudo
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-020029"
echo "rpm -q aide"
rpm -q aide
echo "/usr/sbin/aide --check"
/usr/sbin/aide --check
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-040712"
echo "grep -i kexalgorithms /etc/ssh/sshd_config"
grep -i kexalgorithms /etc/ssh/sshd_config
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010090"
echo "yum list installed screen"
yum list installed screen
echo "yum list installed tmux"
yum list installed tmux
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010375"
echo "sysctl kernel.dmesg_restrict"
sysctl kernel.dmesg_restrict
echo "grep -r kernel.dmesg_restrict /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null"
grep -r kernel.dmesg_restrict /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010199"
echo "ls -l /etc/pam.d/{password,system}-auth"
ls -l /etc/pam.d/{password,system}-auth
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010019"
echo 'rpm -q --queryformat "%{SUMMARY}\n" gpg-pubkey | grep -i "red hat"'
rpm -q --queryformat "%{SUMMARY}\n" gpg-pubkey | grep -i "red hat"
echo "gpg -q --with-fingerprint /etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release"
gpg -q --with-fingerprint /etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-010063"
echo "grep -is disable-user-list /etc/dconf/db/gdm.d/*"
grep -is disable-user-list /etc/dconf/db/gdm.d/*
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------"

echo "RHEL-07-020028"
echo "yum list installed mailx"
yum list installed mailx
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
