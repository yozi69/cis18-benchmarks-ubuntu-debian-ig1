#!/bin/bash

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit 1
fi


export DEBIAN_FRONTEND=noninteractive


echo
echo "----------------------------------------------------------"
echo "Bash script created for Ubuntu 22 / Debian 11 following CIS benchmarks remidations (All IG1 and very few IG2) and implementing them"
echo "Disclaimer: This script does not do audits. For the future it's the users own responsibillty to either create audits scripts to keep checking if remidations are up to date or manually control audits"
echo "Author: Yozi"
echo "----------------------------------------------------------"
echo


#-----------------------------------------------------
# Variables
#-----------------------------------------------------


yellow='\033[1;33m'
green='\033[0;32m'
red='\033[0;31m'
reset='\033[0m'
WAZUH_MANAGER_IP="{YOURWAZUHIP}" # Optional for wazuh log mangement server
WAZUH_REPO="deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" #  Version changes. So this varible must be updatet from time to time
echo



#-----------------------------------------------------
# Update system
#-----------------------------------------------------


echo "Updating and upgrading system to latest.....please wait a minute"
apt-get update -y > /dev/null 2>&1
apt-get upgrade -y > /dev/null 2>&1
echo "Echo update done! starting script..."
echo


update_config_option() {

    print_message="$1"
    file_path="$2"
    option_name="$3"
    option_value="$4"

    # Print the provided message
    echo -e "$print_message"
    

    # Escape forward slashes in the option_value. Else there are issues with the function if arguments contain them.
     escaped_option_value=$(sed 's/[\/@,]/\\&/g' <<< "$option_value")

   
    # Check if the option_name is present (commented or uncommented) in the file
    if grep -qE "^\s*#*\s*${option_name}" "$file_path"; then
    	echo "found"
        # If found, update the line with the option_value
        sed -i "s|^\s*#*\s*${option_name}.*|$escaped_option_value|" "$file_path"
    else
    	echo "not found"
        # If not found, add the new option_name and option_value to the file
        echo "$option_value" >> "$file_path"
    fi

    # Print "Passed!" in green text at the end
    echo -e "${green}Benchmark status: Passed!${reset}"
	# count_benchmarks
    # Print newline after action completion
    echo "moving on to next benchmark..."

    # Print an empty line after the action completion
    echo
    
}



is_package_installed() {

    package="$1"
    dpkg -s "$package" > /dev/null 2>&1
    
}



is_service_enabled() {

    service_name="$1"
    systemctl is-enabled "$service_name" >/dev/null 2>&1
    
}



perform_command_option() {

    message="$1"
    command="$2"

    # Print the initial message
    echo -e "$message"

    # Check if the command is 'rm' and if the file exists
    if [[ "$command" == "rm "* ]]; then
        file_to_remove=${command#rm }
        if [ ! -e "$file_to_remove" ]; then
            echo "File $file_to_remove does not exist."
            echo -e "${green}Benchmark status: Passed!${reset}"
            echo "Moving on to next benchmark..."
            echo
            return
        fi
    fi

    # Check if the command is 'groupadd' and if the group already exists
    if [[ "$command" == "groupadd "* ]]; then
        group_name=${command#groupadd }
        if getent group "$group_name" >/dev/null; then
            echo "Group $group_name already exists. "
            echo -e "${green}Benchmark status: Passed!${reset}"
            echo "Moving on to next benchmark..."
            echo
            return
        fi
    fi

    echo "Running command: $command" > /dev/null 2>&1
    # Execute the command silently
    bash -c "$command" #> /dev/null 2>&1
    command_exit_status=$?
    # Check the return code of the command
    if [ "$command_exit_status" -eq 0 ]; then
    #if $command; then
        echo -e "${green}Benchmark status: Passed!${reset}"
    else
        echo -e "${red}Benchmark status: Failed!${reset} There was an issue with this benchmarks. Please fix cause"
    fi
    # Print newline after action completion
    # count_benchmarks
    echo "Moving on to next benchmark..."

    # Print an empty line after the action completion
    echo

}



perform_manual_command() {

    benchmark="$1"
    remidation="$2"
    command_to_run="$3"

    # ANSI color codes
    echo -e "$benchmark"
    # Print the command to be executed
    echo "You can audit the benchmark with: $command_to_run"

    # Execute the command
    # Check the return code of the command

    echo -e "$remidation"
    echo -e "${yellow}benchmark status: Requires Manual change from user!${reset}"
    # count_benchmarks
    # Print newline after action completion
    echo "Moving on to next benchmark..."

    # Print an empty line after the action completion
    echo
    
}



perform_package_option() {
    message="$1"
    action="$2"
    package="$3"

    # Print the initial message
    echo -e "$message"

    case "$action" in
        "install")
            if is_package_installed "$package"; then
                echo "$package is already installed."
            else
                echo "$package is not installed... system will install now"
                apt-get install -y "$package" > /dev/null 2>&1
            fi
            ;;

        "remove")
            if is_package_installed "$package"; then
                echo "$package is installed... system will  the package now"
                apt-get remove -y "$package" > /dev/null 2>&1
            else
                echo "$package is not installed."
            fi
            ;;

        "purge")
            if is_package_installed "$package"; then
                echo "$package is installed! system will purge the package now"
                apt-get purge -y "$package" > /dev/null 2>&1
            else
                echo "$package is not installed."
            fi
            ;;
            
        "stop")
            if is_service_enabled "$package"; then
                echo "$package is enabled. System will disable it now."
                systemctl --now disable "$package" > /dev/null 2>&1
            else
                echo "$package is not enabled."
            fi
            ;;    

        "disable")
            if is_service_enabled "$package"; then
                echo "$package is enabled. System will disable it now."
                systemctl --now disable "$package" > /dev/null 2>&1
            else
                echo "$package is not enabled."
            fi
            ;;

        "enable")
            if is_service_enabled "$package"; then
                echo "$package is already enabled."
            else
                echo "$package is not enabled, system will enable it now"
                systemctl --now enable "$package" > /dev/null 2>&1
            fi
            ;;

        "restart")
            systemctl restart "$package" > /dev/null 2>&1
            ;;

        *)
            echo "Invalid action: $action"
            return 1
            ;;
    esac

    command_exit_status=$?
    # Check the return code of the command
    if [ "$command_exit_status" -eq 0 ]; then
        echo -e "${green}Benchmark status: Passed!${reset}"
    else
        echo -e "${red}Benchmark status: Failed!${reset} Please check the process for action: $action"
    fi

    # Print newline after action completion
    echo "Moving on to the next benchmark..."

    # Print an empty line after the action completion
    echo
    
}


#-----------------------------------------------------
# --- 1. INITIAL SETUP ---
# ---- 1.1 Filesystem Configuration ----
# --- Will not be called first from main func. Becuase Wazuh requires exec for /tmp when installing agent. ---
#-----------------------------------------------------

filesytem_configuration() {

echo "----> 1.1 Filesystem Configuration <----"
echo "Checking if partitions exist on system"
echo
echo "1.1.2.1 Ensure /tmp is a separate partition (Automated)"
echo "1.1.3.1 Ensure separate partition exists for /var (Automated)"
echo "1.1.4.1 Ensure separate partition exists for /var/tmp (Automated)"
echo "1.1.5.1 Ensure separate partition exists for /var/log (Automated)"
echo "1.1.6.1 Ensure separate partition exists for /var/log/audit "
echo "1.1.7.1 Ensure separate partition exists for /home (Automated)"
echo

partitions=("var" "var/tmp" "tmp" "var/log" "var/log/audit" "home")
partitions_exist=true
for directory in "${partitions[@]}"; do
    if ! findmnt --noheadings --output=source,target | grep -qE "/$directory"; then
        partitions_exist=false
        echo "Directory /$directory does not exist as a separate partition."
        echo -e "${red}Benchmarks status: For seperate partions FAILED! ${reset}"
    fi
done

# Check the flag and execute code or provide a message
echo
if [ "$partitions_exist" = true ]; then
	echo -e "${green}Benchmarks status: For seperate partitions PASSED! ${reset}"
    echo "All required directories exist as separate partitions. Proceeding with 1.1.3.2-1.1.8.3"
    perform_command_option "1.1.3.2 Ensure nodev option set on /var partition" "sed -i -E '/[[:space:]]*\/var[[:space:]]+/ s/(defaults)([[:space:]]+)/\1,nodev,nosuid\2/' /etc/fstab ; mount -o remount /var"
	perform_command_option "1.1.2.3-1.1.24.4 Ensure nosuid,nodev,noexect option set on /tmp and /var/tmp partition (Automated)" "sed -i -E '/[[:space:]]*\/tmp[[:space:]]+/ s/(defaults)([[:space:]]+)/\1,nodev,noexec,nosuid\2/' /etc/fstab ; mount -o remount /tmp ; mount -o remount /var/tmp"
	perform_command_option "1.1.5.2-1.1.5.4 Ensure nosuid,nodev,noexect option set on /var/log" "sed -i -E '/[[:space:]]*\/log[[:space:]]+/ s/(defaults)([[:space:]]+)/\1,nodev,noexec,nosuid\2/' /etc/fstab ; mount -o remount /var/log"
	perform_command_option "1.1.6-2-1.1.6.4 Ensure nosuid,nodev,noexect option set on /var/log/audit" "sed -i -E '/[[:space:]]*\/audit[[:space:]]+/ s/(defaults)([[:space:]]+)/\1,nodev,noexec,nosuid\2/' /etc/fstab ; mount -o remount /var/log/audit"
	perform_command_option "1.1.6-2-1.1.6.4 Ensure nosuid,nodev option set on /home" "sed -i -E '/[[:space:]]*\/home[[:space:]]+/ s/(defaults)([[:space:]]+)/\1,nodev,nosuid\2/' /etc/fstab ; mount -o remount /home"
	perform_command_option "1.1.8.1-1.1.8.3 Ensure nodev,nosuid,noexec option set on /dev/shm partition" "grep -qF \"tmpfs  /dev/shm  tmpfs  defaults,nodev,noexec,nosuid 0 0\" /etc/fstab || echo \"tmpfs  /dev/shm  tmpfs  defaults,nodev,noexec,nosuid 0 0\" | sudo tee -a /etc/fstab ; mount -o remount /dev/shm"
else
    echo "Please create the necessary partitions for the benchmarks to be implemented.... Skipping"
fi
perform_package_option "1.1.9 Disable Automounting (Automated)" "purge" "autofs"
perform_command_option "1.1.10Disable USB Storage (Automated)" "l_mname=\"usb-storage\"; if ! modprobe -n -v \"\$l_mname\" | grep -P -- '^\h*install \/bin\/(true|false)'; then echo -e \" - setting module: \"\$l_mname\" to be not loadable\"; echo -e \"install \$l_mname /bin/false\" >> /etc/modprobe.d/\"\$l_mname\".conf; fi; if lsmod | grep \"\$l_mname\" > /dev/null 2>&1; then echo -e \" - unloading module \"\$l_mname\"\"; modprobe -r \"\$l_mname\"; fi; if ! grep -Pq -- \"^\h*blacklist\h+\$l_mname\b\" /etc/modprobe.d/*; then echo -e \" - deny listing \"\$l_mname\"\"; fi"
echo
}



#-----------------------------------------------------
# ----> 1.3 Configure Software and Patch Management <----
#-----------------------------------------------------

configure_software_and_patch_management() {

echo "---- 1.3 Configure Software and Patch Management ----"
perform_manual_command "Ensure updates, patches, and additional security software are installed (Manual)" "see benchmark for fix" "see benchmark for fix"
perform_manual_command "Ensure package manager repositories are configured)" "see benchmark for fix" "see benchmark for fix"
perform_manual_command "Ensure GPG keys are configured" "see benchmark for fix" "see benchmark for fix"
}


#-----------------------------------------------------
# ----> 1.4 Secure Boot Settings <----
#-----------------------------------------------------

secure_boot_settings() {

echo "---- 1.4 Secure Boot Settings ----"
perform_command_option "1.4.1 Ensure bootloader password is set (Automated)" "read -p \"Enter the superuser username: \" username && grub-mkpasswd-pbkdf2 | tee -a /etc/grub.d/40_custom ; cat /etc/grub.d/40_custom | grep -o 'grub\.pbkdf2.*' | cut -d' ' -f1 | xargs -I {} sh -c \"echo 'cat <<EOF\\nset superusers=\\\"\$username\\\"\\npassword_pbkdf2 \$username {}\\nEOF' > /etc/grub.d/40_custom\" ; sed -i 's/\(CLASS=\"--class gnu-linux --class gnu --class os\)/\1 --unrestricted/' /etc/grub.d/10_linux ; update-grub"
perform_command_option "1.4.2 Ensure permissions on bootloader config are configured" "chown root:root /boot/grub/grub.cfg ; chmod u-wx,go-rwx /boot/grub/grub.cfg"
perform_command_option "1.4.3 Ensure authentication required for single user mode: Please set a strong root password for your machine" "passwd root"

}



#-----------------------------------------------------
# ----> 1.6 Mandatory Access Control <----
#-----------------------------------------------------

mandatory_access_control () {

echo "---- 1.6 Mandatory Access Control ----"
perform_package_option "1.6.1.1 Ensure AppArmor is installed (Automated): apparmor" "install" "apparmor"
perform_package_option "1.6.1.1 Ensure AppArmor is installed (Automated): apparmor-utils" "install" "apparmor-utils" 
perform_command_option "1.6.1.2 Ensure AppArmor is enabled in the bootloader configuration (Automated)" "sed -i 's/\(GRUB_CMDLINE_LINUX=\"[^\"]*\)\"/\1 apparmor=1 security=apparmor\"/' /etc/default/grub ; update-grub > /dev/null 2>&1"
perform_command_option "1.6.1.3 Ensure all AppArmor Profiles are in enforce or complain mode (Automated) + 1.6.1.4 Ensure all AppArmor Profiles are enforcing" "aa-enforce /etc/apparmor.d/* > /dev/null 2>&1"
}



#-----------------------------------------------------
# ----> 1.7 Command Line Warning Banners <----
#-----------------------------------------------------

command_line_warning_banners() {

echo "----> 1.7 Command Line Warning Banners <----"
perform_command_option "1.8.1.1 Ensure message of the day is configured properly (Automated)" "rm /etc/motd"
perform_command_option "1.8.1.2 Ensure local login warning banner is configured properly (Automated)" "echo 'Authorized uses only. All activity may be monitored and reported.' > /etc/issue"
perform_command_option "1.8.1.3 Ensure remote login warning banner is configured properly (Automated)" "echo 'Authorized uses only. All activity may be monitored and reported.' > /etc/issue.net"
#1.8.1.4 Ensure permissions on /etc/motd are configured (Automated), SKIPPING because /etc/motd was deleted
perform_command_option "1.8.1.5 Ensure permissions on /etc/issue are configured (Automated)" "chown root:root /etc/issue"
perform_command_option "1.8.1.5 Ensure permissions on /etc/issue are configured (Automated)" "chmod u-x,go-wx /etc/issue"
perform_command_option "1.8.1.6 Ensure permissions on /etc/issue.net are configured" "chown root:root /etc/issue.net"
perform_command_option "1.8.1.6 Ensure permissions on /etc/issue.net are configured" "chmod u-x,go-wx /etc/issue.net"

}


#-----------------------------------------------------
# ----> 1.8 GNOME Display Manager <----
#-----------------------------------------------------

gnome_display_manager() {

echo "----> 1.8 GNOME Display Manager <----"
# In this case, no display manager will be used. Skipping 1.8.2-1.8.10
perform_package_option "1.8.1 Ensure GNOME Display Manager is removed (Automated)" "purge" "gdm3"

}



#-----------------------------------------------------
# ----> 2.2 Special Purpose Services <-----
#-----------------------------------------------------

special_purpose_services() {

echo "----> 2.2 Special Purpose Services <----"
perform_package_option "2.1.1 Ensure xinetd is not installed (Automated).. removing now" "remove" "xinetd"
perform_package_option "2.1.1 Ensure xinetd is not installed (Automated).. removing now" "purge" "xserver-xorg*"
perform_package_option "2.1.2 Ensure openbsd-inetd is not installed (Automated).. removing now" "remove" "openbsd-inetd"
perform_package_option "2.2.2 Ensure X Window System is not installed (Automated)" "purge" "xserver-xorg*"
perform_package_option "2.2.3 Ensure Avahi Server is not enabled (Automated)" "stop" "avahi-daaemon.service  avahi-daemon.socket"
perform_package_option "2.2.3 Ensure Avahi Server is not enabled (Automated)" "purge" "avahi-daemon"
perform_package_option "2.2.4 Ensure CUPS is not enabled (Automated)" "disable" "cups"
perform_package_option "2.2.5 Ensure DHCP Server is not enabled (Automated)" "disable" "isc-dhcp-server"
perform_package_option "2.2.5 Ensure DHCP Server is not enabled (Automated)" "disable" "isc-dhcp-server6"
perform_package_option "2.2.6 Ensure LDAP server is not enabled" "disable" "slapd"
perform_package_option "2.2.7 Ensure NFS and RPC are not enabled (Automated)" "disable" "nfs-server"
perform_package_option "2.2.7 Ensure NFS and RPC are not enabled (Automated)" "disable" "nfs-kernel-server"
perform_package_option "2.2.7 Ensure NFS and RPC are not enabled (Automated)" "disable" "rpcbind"
perform_package_option "2.2.8 Ensure DNS Server is not enabled (Automated)" "disable" "bind9"
perform_package_option "2.2.9 Ensure FTP Server is not enabled (Automated)" "disable" "vsftpd"
perform_package_option "2.2.10 Ensure HTTP server is not enabled (Automated)" "disable" "apache2"
perform_package_option "2.2.11 Ensure email services are not enabled (Automated)" "purge" "dovecot dovecot-imapd dovecot-pop3d"
perform_package_option "2.2.12 Ensure HTTP PROXY is not installed (Automated)" "purge" "squid"
perform_package_option "2.2.13 Ensure SNMP Server is not enabled (Automated)" "disable" "snmpd snmp"
perform_package_option "2.2.XX Ensure Samba Server is not enabled (Automated)" "purge" "samba"
perform_package_option "2.2.14 Ensure NIS Server is not installed (Automated)" "purge" "nis"
perform_package_option "2.2.15 Ensure postfix is not installed (Automated)" "purge" "postfix"
perform_package_option "2.2.16 Ensure rsync service is not enabled/installed (Automated)" "purge" "rsync"
 
}



#-----------------------------------------------------
# ----> 2.3 Service Clients <----
#-----------------------------------------------------

service_clients() {
echo "---- 2.3 Service Clients ----"

# "2.2.17 Ensure NIS Server is not enabled/installed (Automated)" Allready done, skip
perform_package_option "2.3.2 Ensure rsh client is not installed (Automated)" "purge" "rsh-client"
perform_package_option "2.3.3 Ensure talk client is not installed (Automated)" "purge" "talk"
perform_package_option "2.3.4 Ensure telnet client is not installed (Automated)" "purge" "telnet"
perform_package_option "2.3.5 Ensure LDAP client is not installed (Automated)" "purge" "ldap-utils"
perform_package_option "2.3.6 Ensure RPC is not installed (Automated)" "purge" "rpcbind"

}



#-----------------------------------------------------
# ----> 3 Network Configuration <----
# ---- > 3.1 Disable unused network protocols and devices <----
#-----------------------------------------------------

disable_unused_network_protocols_and_devices() {

echo "---- > 3.1 Disable unused network protocols and devices. IVP4 ONLY <----"
perform_command_option "3.1.1 Ensure system is checked to determine if IPv6 is enabled" "printf \"net.ipv6.conf.all.disable_ipv6 = 1 net.ipv6.conf.default.disable_ipv6 = 1 \" >> /etc/sysctl.d/60-disable_ipv6.conf ; sysctl -w net.ipv6.conf.all.disable_ipv6=1 ; sysctl -w net.ipv6.conf.default.disable_ipv6=1 ; sysctl -w net.ipv6.route.flush=1"
perform_command_option  "3.3.4 Ensure suspicious packets are logged (Automated)" "l_output=\"\"; l_output2=\"\"; l_parlist=\"net.ipv4.conf.all.log_martians=1 net.ipv4.conf.default.log_martians=1\"; l_searchloc=\"/run/sysctl.d/*.conf /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf \$([ -f /etc/default/ufw ] && awk -F= '/^\\s*IPT_SYSCTL=/ {print \$2}' /etc/default/ufw)\"; l_kpfile=\"/etc/sysctl.d/60-netipv4_sysctl.conf\"; KPF() { l_fafile=\"\$(grep -s -- \"^\\s*\$l_kpname\" \$l_searchloc | grep -Pv -- \"\\h*=\\h*\$l_kpvalue\\b\\h*\" | awk -F: '{print \$1}')\"; for l_bkpf in \$l_fafile; do echo -e \"\\n - Commenting out \\\"\$l_kpname\\\" in \\\"\$l_bkpf\\\"\"; sed -ri \"/\$l_kpname/s/^/# /\" \"\$l_bkpf\"; done; if ! grep -Pslq -- \"^\\h*\$l_kpname\\h*=\\h*\$l_kpvalue\\b\\h*\" \$l_searchloc; then echo -e \"\\n - Setting \\\"\$l_kpname\\\" to \\\"\$l_kpvalue\\\" in \\\"\$l_kpfile\\\"\"; echo \"\$l_kpname = \$l_kpvalue\" >> \"\$l_kpfile\"; fi; l_krp=\"\$(sysctl \"\$l_kpname\" | awk -F= '{print \$2}' | xargs)\"; if [ \"\$l_krp\" != \"\$l_kpvalue\" ]; then echo -e \"\\n - Updating \\\"\$l_kpname\\\" to \"\$l_kpvalue\" in the active kernel parameters\"; sysctl -w \"\$l_kpname=\$l_kpvalue\"; sysctl -w \"\$(awk -F'.' '{print \$1\".\"\$2\".route.flush=1\"}' <<< \"\$l_kpname\")\"; fi; }; for l_kpe in \$l_parlist; do l_kpname=\"\$(awk -F= '{print \$1}' <<< \"\$l_kpe\")\"; l_kpvalue=\"\$(awk -F= '{print \$2}' <<< \"\$l_kpe\")\"; KPF; done"

}



#-----------------------------------------------------
# ---->  3.5.3.2 Configure IPv4 iptables <----
#-----------------------------------------------------

configure_firewall_iptables() {

echo " ----> 3.5.3 Configure iptables. IVP4 ONLY <----"
perform_package_option "3.5.3.1.1 Ensure iptables packages are installed (Automated)" "install" "iptables"
perform_package_option "3.5.3.1.1 Ensure iptables packages are installed (Automated)" "install" "iptables-persistent"
perform_package_option "3.5.3.1.2 Ensure nftables is not installed with iptables" "purge" "nftables"
perform_package_option "3.5.3.1.3 Ensure ufw is uninstalled or disabled with iptables" "purge" "ufw"
iptables -F
perform_command_option "Configuring rules with extra_rules.xt file made by user. It covers: 3.5.3.2.2 Ensure iptables loopback traffic is configured, 3.5.3.2.1 Ensure iptables default deny firewall policy (Automated), Ensure iptables outbound and established connections are configured, 3.5.3.2.4 Ensure iptables firewall rules exist for all open ports" "iptables-restore < iptables_rules.txt"
service netfilter-persistent save > /dev/null 2>&1


}


#--------------------------------------------------------------------------------------
# ----> 4.1 Configure System Accounting (auditd) & 4.1.2 Configure Data Retention <----
#--------------------------------------------------------------------------------------

configure_auditing() {

echo " ----> 4.1 Configure System Accounting (auditd) & 4.1.2 Configure Data Retention<----"
perform_package_option "4.1.1.1 Ensure auditd is installed (Automated)" "install" "auditd"
perform_package_option "4.1.1.1 Ensure auditd is installed (Automated)" "install" "audispd-plugins"
perform_package_option "4.1.1.2 Ensure auditd service is enabled and active (Automated)" "enable" "auditd"
perform_command_option "4.1.1.3 Ensure auditing for processes that start prior to auditd is" "sed -i 's/\(GRUB_CMDLINE_LINUX=\"[^\"]*\)\"/\1 audit=1\"/' /etc/default/grub"
perform_command_option "4.1.1.4 Ensure audit_backlog_limit is sufficient (Automated)" "sed -i 's/\(GRUB_CMDLINE_LINUX=\"[^\"]*\)\"/\1 audit_backlog_limit=8192\"/' /etc/default/grub ; update-grub >/dev/null 2>&1"	
update_config_option "4.1.2.1 Ensure audit log storage size is configured (Automated)" "/etc/audit/auditd.conf" "max_log_file =" "max_log_file = 16"
update_config_option "4.1.2.2 Ensure audit logs are not automatically deleted" "/etc/audit/auditd.conf" "max_log_file_action =" "max_log_file_action = keep_logs"
update_config_option "4.1.2.3 Ensure system is disabled when audit logs are full" "/etc/audit/auditd.conf" "space_left_action =" "space_left_action = email" 
update_config_option "4.1.2.3 Ensure system is disabled when audit logs are full" "/etc/audit/auditd.conf" "action_mail_acct =" "action_mail_acct = root" 
update_config_option "4.1.2.3 Ensure system is disabled when audit logs are full" "/etc/audit/auditd.conf" "admin_space_left_action =" "admin_space_left_action = halt" 

}



#-----------------------------------------------------
# ----> 4.1.3 Configure auditd rules <----
#-----------------------------------------------------

configure_audit_rules() {

# clears existing audit.rules (under rules.d/ and creates new one with needed rules):
rm /etc/audit/rules.d/audit.rules
cat >> /etc/audit/rules.d/40-beginning.rules << EOF 
-D
-b 8192
-f 1 --backlog_wait_time 60000
EOF
echo "System will now load auditd rules for IG1...."
echo "---> 4.1.3 Configure auditd rules <---"
perform_command_option "4.1.3.6 Ensure use of privileged commands are collected" "[ ! -f \"/etc/audit/rules.d/50-privileged.rules\" ] && touch \"/etc/audit/rules.d/50-privileged.rules\"; UID_MIN=\$(awk '/^\\s*UID_MIN/{print \$2}' /etc/login.defs); AUDIT_RULE_FILE=\"/etc/audit/rules.d/50-privileged.rules\"; NEW_DATA=(); for PARTITION in \$(findmnt -n -l -k -it \$(awk '/nodev/ { print \$2 }' /proc/filesystems | paste -sd,) | grep -Pv \"noexec|nosuid\" | awk '{print \$1}'); do readarray -t DATA < <(find \"\${PARTITION}\" -xdev -perm /6000 -type f | awk -v UID_MIN=\${UID_MIN} '{print \"-a always,exit -F path=\" \$1 \" -F perm=x -F auid>=\" UID_MIN \" -F auid!=unset -k privileged\"}'); for ENTRY in \"\${DATA[@]}\"; do NEW_DATA+=(\"\${ENTRY}\"); done; done; readarray -t OLD_DATA < \"\${AUDIT_RULE_FILE}\" 2>/dev/null; COMBINED_DATA=( \"\${OLD_DATA[@]}\" \"\${NEW_DATA[@]}\" ); printf '%s\\n' \"\${COMBINED_DATA[@]}\" | sort -u > \"\${AUDIT_RULE_FILE}\"" 
perform_command_option "4.1.3.12 Ensure login and logout events are collected" "cat > /etc/audit/rules.d/50-login-logout.rules<< EOF
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock -p wa -k logins
EOF"
perform_command_option "4.1.3.13 Ensure file deletion events by users are collected" "UID_MIN=\$(awk '/^\s*UID_MIN/{print \$2}' /etc/login.defs); [ -n \"\${UID_MIN}\" ] && printf \"\\n-a always,exit -F arch=b64 -S rename,unlink,unlinkat,renameat -F auid>=\${UID_MIN} -F auid!=unset -F key=delete\\n-a always,exit -F arch=b32 -S rename,unlink,unlinkat,renameat -F auid>=\${UID_MIN} -F auid!=unset -F key=delete\\n\" >> /etc/audit/rules.d/50-delete.rules || printf \"ERROR: Variable 'UID_MIN' is unset.\\n\""
perform_command_option "# 4.1.3.15 Ensure successful and unsuccessful attempts to use the chcon" "UID_MIN=\$(awk '/^\\s*UID_MIN/{print \$2}' /etc/login.defs); [ -n \"\${UID_MIN}\" ] && printf \"\\n-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=\${UID_MIN} -F auid!=unset -k perm_chng\\n\" >> /etc/audit/rules.d/50-perm_chng.rules || printf \"ERROR: Variable 'UID_MIN' is unset.\\n\""
perform_command_option "# 4.1.3.16 Ensure successful and unsuccessful attempts to use the setfacl" "UID_MIN=\$(awk '/^\\s*UID_MIN/{print \$2}' /etc/login.defs); [ -n \"\${UID_MIN}\" ] && printf \"\\n-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=\${UID_MIN} -F auid!=unset -k perm_chng\\n\" >> /etc/audit/rules.d/50-perm_chng.rules || printf \"ERROR: Variable 'UID_MIN' is unset.\\n\""
perform_command_option "# 4.1.3.17 Ensure successful and unsuccessful attempts to use the chacl command are recorded (Automated)" "UID_MIN=\$(awk '/^\\s*UID_MIN/{print \$2}' /etc/login.defs); [ -n \"\${UID_MIN}\" ] && printf \"\\n-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=\${UID_MIN} -F auid!=unset -k perm_chng\\n\" >> /etc/audit/rules.d/50-perm_chng.rules || printf \"ERROR: Variable 'UID_MIN' is unset.\\n\""
perform_command_option "# 4.1.3.18 Ensure successful and unsuccessful attempts to use the usermod command are recorded (Automated)" "UID_MIN=\$(awk '/^\\s*UID_MIN/{print \$2}' /etc/login.defs); [ -n \"\${UID_MIN}\" ] && printf \"\\n-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=\${UID_MIN} -F auid!=unset -k usermod\\n\" >> /etc/audit/rules.d/50-usermod.rules || printf \"ERROR: Variable 'UID_MIN' is unset.\\n\""
perform_command_option "# 4.1.3.19 Ensure kernel module loading unloading and modification is collected (Automated)" "UID_MIN=\$(awk '/^\\s*UID_MIN/{print \$2}' /etc/login.defs); [ -n \"\${UID_MIN}\" ] && printf \"\\n-a always,exit -F arch=b64 -S init_module,finit_module,delete_module,create_module,query_module -F auid>=\${UID_MIN} -F auid!=unset -k kernel_modules \\n-a always,exit -F path=/usr/bin/kmod -F perm=x -F auid>=\${UID_MIN} -F auid!=unset -k kernel_modules\\n\" >> /etc/audit/rules.d/50-kernel_modules.rules || printf \"ERROR: Variable 'UID_MIN' is unset.\\n\""
perform_command_option "# 4.1.3.20 Ensure the audit configuration is immutable (Automated)" "echo \"-e 2\" >> /etc/audit/rules.d/99-finalize.rules"
perform_command_option "# 4.1.4.1 Ensure audit log files are mode 0640 or less permissive" "[ -f /etc/audit/auditd.conf ] && find \"\$(dirname \$(awk -F \"=\" '/^\s*log_file/ {print \$2}' /etc/audit/auditd.conf | xargs))\" -type f \( ! -perm 600 -a ! -perm 0400 -a ! -perm 0200 -a ! -perm 0000 -a ! -perm 0640 -a ! -perm 0440 -a ! -perm 0040 \) -exec chmod u-x,g-wx,o-rwx {} +"
perform_command_option "4.1.4.2 Ensure only authorized users own audit log files" "[ -f /etc/audit/auditd.conf ] && find \"\$(dirname \$(awk -F \"=\" '/^\s*log_file/ {print \$2}' /etc/audit/auditd.conf | xargs))\" -type f ! -user root -exec chown root {} +"
perform_command_option "# 4.1.4.3 Ensure only authorized groups are assigned ownership of audit log files (Automated)" "find \$(dirname \$(awk -F\"=\" '/^\s*log_file/ {print \$2}' /etc/audit/auditd.conf | xargs)) -type f \( ! -group adm -a ! -group root \) -exec chgrp adm {} + ; chgrp adm /var/log/audit/ ; sed -ri 's/^\s*#?\s*log_group\s*=\s*\S+(\s*#.*)?.*$/log_group = adm\1/' /etc/audit/auditd.conf ; systemctl restart auditd"

}



#-----------------------------------------------------
# ----> 4.1.4 Configure auditd file access <----
#-----------------------------------------------------

configure_auditd_file_access() {

echo "----> 4.1.4 Configure auditd file access <----"
perform_command_option "4.1.4.4 Ensure the audit log directory is 0750 or more restrictive" "chmod g-w,o-rwx \"\$(dirname \$(awk -F\"=\" '/^\s*log_file/ {print \$2}' /etc/audit/auditd.conf))\""
perform_command_option "# 4.1.4.5 Ensure audit configuration files are 640 or more restrictive" "find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) ! -user root -exec chown root {} +"
perform_command_option "4.1.4.7 Ensure audit configuration files belong to group root" "find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) ! -group root -exec chgrp root {} +"
perform_command_option "4.1.4.8 Ensure audit tools are 755 or more restrictive (Automated)" "chmod go-w /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules"
perform_command_option "4.1.4.9 Ensure audit tools are owned by root (Automated)" "chown root /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules"
perform_command_option "4.1.4.10 Ensure audit tools belong to group root Automated" "chmod go-w /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules ; chown root:root /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules"
perform_package_option "4.1.4.11 Ensure cryptographic mechanisms are used to protect  the integrity of audit tools (Automated)" "install" "aide"
perform_command_option "4.1.4.11 Ensure cryptographic mechanisms are used to protect  the integrity of audit tools (Automated)" "cat >> /etc/aide/aide.conf << EOF 
/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512 
/sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512
EOF"
echo "System will now load auditd rules for IG1...."
augenrules --load >/dev/null 2>&1
systemctl restart auditd

}



#-----------------------------------------------------
# ----> 4.2.1 Configure journald <----
#-----------------------------------------------------

configure_journald() {

echo "----> 4.2.1 Configure journald <----"
perform_package_option "4.2.1.1.4 Ensure journald is not configured to recieve logs from aremote client (Automated)" "disable" "systemd-journal-remote.socket"
perform_command_option "4.2.1.3 Ensure journald is configured to compress large log files (Automated)" "echo 'Compress=yes' >> /etc/systemd/journald.conf ; systemctl restart systemd-journald"
perform_command_option "4.2.1.4 Ensure journald is configured to write logfiles to persistent disk (Automated)" "echo 'Storage=persistent' >> /etc/systemd/journald.conf ; systemctl restart systemd-journald" 
perform_command_option "4.2.1.5 Ensure journald is not configured to send logs to rsyslog" "sed -i '/ForwardToSyslog=yes/d' /etc/systemd/journald.conf"
perform_command_option "4.2.1.6 Ensure journald log rotation is configured per site policy" "sed -Ei 's/^#?(\s*SystemMaxUse\s*=).*/\1=500M/; s/^#?(\s*SystemKeepFree\s*=).*/\1=100M/; s/^#?(\s*RuntimeMaxUse\s*=).*/\1=50M/; s/^#?(\s*RuntimeKeepFree\s*=).*/\1=20M/; s/^#?(\s*MaxFileSec\s*=).*/\1=1week/' /etc/systemd/journald.conf"
perform_manual_command "4.2.1.7 Ensure journald default file permissions configured" "See 4.2.1.7 remidation!"
perform_command_option "4.2.3 Ensure all logfiles have appropriate permissions and" "find /var/log -type f | while read -r fname; do bname=\"\$(basename \"\$fname\")\"; case \"\$bname\" in lastlog | lastlog.* | wtmp | wtmp.* | btmp | btmp.*) ! stat -Lc \"%a\" \"\$fname\" | grep -Pq -- '^\\h*[0,2,4,6][0,2,4,6][0,4]\\h*$' && echo -e \"- changing mode on \\\"\$fname\\\"\" && chmod ug-x,o-wx \"\$fname\"; ! stat -Lc \"%U\" \"\$fname\" | grep -Pq -- '^\\h*root\\h*$' && echo -e \"- changing owner on \\\"\$fname\\\"\" && chown root \"\$fname\"; ! stat -Lc \"%G\" \"\$fname\" | grep -Pq -- '^\\h*(utmp|root)\\h*$' && echo -e \"- changing group on \\\"\$fname\\\"\" && chgrp root \"\$fname\";; secure | auth.log) ! stat -Lc \"%a\" \"\$fname\" | grep -Pq -- '^\\h*[0,2,4,6][0,4]0\\h*$' && echo -e \"- changing mode on \\\"\$fname\\\"\" && chmod u-x,g-wx,o-rwx \"\$fname\"; ! stat -Lc \"%U\" \"\$fname\" | grep -Pq -- '^\\h*(syslog|root)\\h*$' && echo -e \"- changing owner on \\\"\$fname\\\"\" && chown root \"\$fname\"; ! stat -Lc \"%G\" \"\$fname\" | grep -Pq -- '^\\h*(adm|root)\\h*$' && echo -e \"- changing group on \\\"\$fname\\\"\" && chgrp root \"\$fname\";; SSSD | sssd) ! stat -Lc \"%a\" \"\$fname\" | grep -Pq -- '^\\h*[0,2,4,6][0,2,4,6]0\\h*$' && echo -e \"- changing mode on \\\"\$fname\\\"\" && chmod ug-x,o-rwx \"\$fname\"; ! stat -Lc \"%U\" \"\$fname\" | grep -Piq -- '^\\h*(SSSD|root)\\h*$' && echo -e \"- changing owner on \\\"\$fname\\\"\" && chown root \"\$fname\"; ! stat -Lc \"%G\" \"\$fname\" | grep -Piq -- '^\\h*(SSSD|root)\\h*$' && echo -e \"- changing group on \\\"\$fname\\\"\" && chgrp root \"\$fname\";; gdm | gdm3) ! stat -Lc \"%a\" \"\$fname\" | grep -Pq -- '^\\h*[0,2,4,6][0,2,4,6]0\\h*$' && echo -e \"- changing mode on \\\"\$fname\\\"\" && chmod ug-x,o-rwx; ! stat -Lc \"%U\" \"\$fname\" | grep -Pq -- '^\\h*root\\h*$' && echo -e \"- changing owner on \\\"\$fname\\\"\" && chown root \"\$fname\"; ! stat -Lc \"%G\" \"\$fname\" | grep -Pq -- '^\\h*(gdm3?|root)\\h*$' && echo -e \"- changing group on \\\"\$fname\\\"\" && chgrp root \"\$fname\";; *.journal) ! stat -Lc \"%a\" \"\$fname\" | grep -Pq -- '^\\h*[0,2,4,6][0,4]0\\h*$' && echo -e \"- changing mode on \\\"\$fname\\\"\" && chmod u-x,g-wx,o-rwx \"\$fname\"; ! stat -Lc \"%U\" \"\$fname\" | grep -Pq -- '^\\h*root\\h*$' && echo -e \"- changing owner on \\\"\$fname\\\"\" && chown root \"\$fname\"; ! stat -Lc \"%G\" \"\$fname\" | grep -Pq -- '^\\h*(systemd-journal|root)\\h*$' && echo -e \"- changing group on \\\"\$fname\\\"\" && chgrp root \"\$fname\";; *) ! stat -Lc \"%a\" \"\$fname\" | grep -Pq -- '^\\h*[0,2,4,6][0,4]0\\h*$' && echo -e \"- changing mode on \\\"\$fname\\\"\" && chmod u-x,g-wx,o-rwx \"\$fname\"; ! stat -Lc \"%U\" \"\$fname\" | grep -Pq -- '^\\h*(syslog|root)\\h*$' && echo -e \"- changing owner on \\\"\$fname\\\"\" && chown root \"\$fname\" ; ! stat -Lc \"%G\" \"\$fname\" | grep -Pq -- '^\\h*(adm|root)\\h*$' && echo -e \"- changing group on \\\"\$fname\\\"\" && chgrp root \"\$fname\";; esac; done; echo -e \"- End remediation - logfiles have appropriate permissions and ownership\n\""
perform_package_option "Removing rsyslog, since its not being used or configured. journald is being used instead" "purge" "rsyslog"


#---------------------------------------------------------------------------------------------------------------------------------------------
#  ----> 4.2.1.1.1 - 4.2.1.1.3 Replaceing Remote log mangemeng using instead WAZUH <----
# ---> OPTIONAL: Uncomment in main function, if you do not wish to use <----
#---------------------------------------------------------------------------------------------------------------------------------------------


}

configure_remotelog_server_wazuh() {

echo "---> 4.2.1.1.1 - 4.2.1.1.3 Replaceing Remote log mangemeng using instead WAZUH <----"
echo
apt install gpg -y > /dev/null 2>&1
apt install curl -y > /dev/null 2>&1
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
echo "$WAZUH_REPO" | tee -a /etc/apt/sources.list.d/wazuh.list
apt-get update -y
WAZUH_MANAGER="$WAZUH_MANAGER_IP" apt-get install wazuh-agent
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent
echo

}



#-----------------------------------------------------------
# ---> 4. Access, Authentication and Authorization <----
# ----> 4.1 Configure time-based job schedulers (CRON) <----
#-----------------------------------------------------------

configure_timebased_jobs_schedulers() {

echo "--- 4.1 Configure time-based job schedulers (CRON) ----"
perform_package_option "4.1.1 Ensure cron daemon is enabled (Automated)" "enable" "cron"
perform_command_option "4.1.2 Ensure permissions on /etc/crontab are configured (Automated)" "chown root:root /etc/crontab ; chmod og-rwx /etc/crontab"
perform_command_option "4.1.3 Ensure permissions on /etc/cron.hourly are configured" "chown root:root /etc/cron.hourly/ ; chmod og-rwx /etc/cron.hourly"
perform_command_option "4.1.4 Ensure permissions on /etc/cron.daily are configured (Automated)" "chown root:root /etc/cron.daily/ ; chmod og-rwx /etc/cron.daily/"
perform_command_option "4.1.5 Ensure permissions on /etc/cron.daily are configured (Automated)" "chown root:root /etc/cron.weekly/ ; chmod og-rwx /etc/cron.weekly/"
perform_command_option "5.1.6 Ensure permissions on /etc/cron.monthly are configured" "chown root:root /etc/cron.monthly/ ; chmod og-rwx /etc/cron.monthly/"
perform_command_option "4.1.7 Ensure permissions on /etc/cron.daily are configured (Automated)" "chown root:root /etc/cron.d/ ; chmod og-rwx /etc/cron.d/"
perform_command_option "4.1.8 Ensure cron is restricted to authorized users (Automated)" "if dpkg-query -W cron > /dev/null 2>&1; then l_file=\"/etc/cron.allow\"; l_mask=\"0137\"; l_maxperm=\"\$(printf \"%o\" \$((0777 & ~\$l_mask)))\"; if [ -e /etc/cron.deny ]; then echo -e \" - Removing \\\"/etc/cron.deny\\\"\"; rm -f /etc/cron.deny; fi; if [ ! -e /etc/cron.allow ]; then echo -e \" - creating \\\"\$l_file\\\"\"; touch \"\$l_file\"; fi; while read l_mode l_fown l_fgroup; do if [ \$(( \$l_mode & \$l_mask )) -gt 0 ]; then echo -e \" - Removing excessive permissions from \\\"\$l_file\\\"\"; chmod \"u-x,g-wx,o-rwx\" \"\$l_file\"; fi; if [ \"\$l_fown\" != \"root\" ]; then echo -e \" - Changing owner on \\\"\$l_file\\\" from: \\\"\$l_fown\\\" to: \\\"root\\\"\"; chown \"root\" \"\$l_file\"; fi; if [ \"\$l_fgroup\" != \"crontab\" ]; then echo -e \" - Changing group owner on \\\"\$l_file\\\" from: \\\"\$l_fgroup\\\" to: \\\"crontab\\\"\"; chgrp crontab \"\$l_file\"; fi; done < <(stat -Lc \"%#a %U %G\" \"\$l_file\"); else echo -e \"- cron is not installed on the system, no remediation required\\n\"; fi"
perform_command_option "4.1.9 Ensure at is restricted to authorized users (Automated)" "if dpkg-query -W at > /dev/null 2>&1; then l_file=\"/etc/at.allow\"; l_mask=\"0137\"; l_maxperm=\"\$(printf \"%o\" \$((0777 & ~\$l_mask)))\"; if [ -e /etc/at.deny ]; then echo -e \" - Removing \\\"/etc/at.deny\\\"\"; rm -f /etc/at.deny; fi; if [ ! -e /etc/at.allow ]; then echo -e \" - creating \\\"\$l_file\\\"\"; touch \"\$l_file\"; fi; while read l_mode l_fown l_fgroup; do if [ \$(( \$l_mode & \$l_mask )) -gt 0 ]; then echo -e \" - Removing excessive permissions from \\\"\$l_file\\\"\"; chmod \"u-x,g-wx,o-rwx\" \"\$l_file\"; fi; if [ \"\$l_fown\" != \"root\" ]; then echo -e \" - Changing owner on \\\"\$l_file\\\" from: \\\"\$l_fown\\\" to: \\\"root\\\"\"; chown \"root\" \"\$l_file\"; fi; if [ \"\$l_fgroup\" != \"root\" ]; then echo -e \" - Changing group owner on \\\"\$l_file\\\" from: \\\"\$l_fgroup\\\" to: \\\"root\\\"\"; chgrp \"root\" \"\$l_file\"; fi; done < <(stat -Lc \"%#a %U %G\" \"\$l_file\"); else echo -e \"- at is not installed on the system, no remediation required\\n\"; fi"

}


#-----------------------------------------------------
# ----> 4.2 Configure SSH Server <----
#-----------------------------------------------------

configure_ssh_server() {

echo "---- 4.2 Configure SSH Server ----"
perform_command_option "4.2.1 Ensure permissions on /etc/ssh/sshd_config are configured (Automated)" "chown root:root /etc/ssh/sshd_config ; chmod og-rwx /etc/ssh/sshd_config"
perform_command_option "4.2.2 Ensure permissions on SSH private host key files are configured (Automated)" "l_skgn=\"ssh_keys\"; l_skgid=\"\$(awk -F: '(\$1 == \"'\"\$l_skgn\"'\"){print \$3}' /etc/group)\"; awk '{print}' <<< \"\$(find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec stat -L -c \"%n %#a %U %G %g\" {} +)\" | (while read -r l_file l_mode l_owner l_group l_gid; do [ -n \"\$l_skgid\" ] && l_cga=\"\$l_skgn\" || l_cga=\"root\"; [ \"\$l_gid\" = \"\$l_skgid\" ] && l_pmask=\"0137\" || l_pmask=\"0177\"; l_maxperm=\"\$( printf '%o' \$(( 0777 & ~\$l_pmask )) )\"; if [ \$(( \$l_mode & \$l_pmask )) -gt 0 ]; then echo -e \" - File: \"\$l_file\" is mode \"\$l_mode\" changing to mode: \"\$l_maxperm\"\"; if [ -n \"\$l_skgid\" ]; then chmod u-x,g-wx,o-rwx \"\$l_file\"; else chmod u-x,go-rwx \"\$l_file\"; fi; fi; if [ \"\$l_owner\" != \"root\" ]; then echo -e \" - File: \"\$l_file\" is owned by: \"\$l_owner\" changing owner to \"root\"\"; chown root \"\$l_file\"; fi; if [ \"\$l_group\" != \"root\" ] && [ \"\$l_gid\" != \"\$l_skgid\" ]; then echo -e \" - File: \"\$l_file\" is owned by group \"\$l_group\" should belong to group \"\$l_cga\"\"; chgrp \"\$l_cga\" \"\$l_file\"; fi; done)" 
perform_command_option "4.2.3 Ensure permissions on SSH public host key files are configured(Automated)" "find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chmod u-x,go-wx {} \; ; find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chown root:root {} \;"
perform_manual_command "4.2.4 Ensure SSH access is limited (Automated)" "Remidation: Add to sshd_config (or sshd_config/*) allowusers userlist, allowgroups grouplist, denyusers userlist, denygroups grouplist, depending on who should have SSH access or denied SSH access" 'grep -Pis "^\h*(allow|deny)(users|groups)\h+\H+(\h+.*)?$" /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf'
update_config_option "4.2.5 Ensure SSH LogLevel is appropriate (Automated)" "/etc/ssh/sshd_config.d/custom_config.conf" "loglevel" "loglevel VERBOSE"
update_config_option "4.2.6 Ensure SSH PAM is enabled (Automated)" "/etc/ssh/sshd_config.d/custom_config.conf" "UsePAM" "UsePAM yes"
update_config_option "4.2.22 Ensure SSH Idle Timeout Interval is configured" "/etc/ssh/sshd_config.d/custom_config.conf" "ClientAliveCountMax" "ClientAliveCountMax 3"
update_config_option "4.2.22 Ensure SSH Idle Timeout Interval is configured" "/etc/ssh/sshd_config.d/custom_config.conf" "ClientAliveInterval" "ClientAliveInterval 15"
update_config_option "4.2.20 Ensure SSH LoginGraceTime is set to one minute or less" "/etc/ssh/sshd_config.d/custom_config.conf" "LoginGraceTime " "LoginGraceTime 60"
update_config_option "4.2.21 Ensure SSH MaxSessions is set to 10 or less (Automated)" "/etc/ssh/sshd_config.d/custom_config.conf" "MaxSessions" "MaxSessions 10"
update_config_option "4.2.19 Ensure SSH MaxStartups is configured (Automated)" "/etc/ssh/sshd_config.d/custom_config.conf" "Maxstartups" "Maxstartups 10:30:60"
update_config_option "4.2.18 Ensure SSH MaxAuthTries is set to 4 or less (Automated)" "/etc/ssh/sshd_config.d/custom_config.conf" "MaxAuthTries" "MaxAuthTries 4"
update_config_option "4.2.17 Ensure SSH warning banner is configured (Automated)" "/etc/ssh/sshd_config.d/custom_config.conf" "Banner" "Banner /etc/issue.net"
update_config_option "4.2.16 Ensure SSH AllowTcpForwarding is disabled (Automated)" "/etc/ssh/sshd_config.d/custom_config.conf" "AllowTcpForwarding" "AllowTcpForwarding no"
update_config_option "4.2.14 Ensure only strong MAC algorithms are used (Automated)" "/etc/ssh/sshd_config.d/custom_config.conf" "MACs" "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256"
update_config_option "4.2.13 Ensure only strong Ciphers are used (Automated)" "/etc/ssh/sshd_config.d/custom_config.conf" "Ciphers" "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"
update_config_option "4.2.12 Ensure SSH X11 forwarding is disabled (Automated)" "/etc/ssh/sshd_config.d/custom_config.conf" "X11Forwarding" "X11Forwarding no"
update_config_option "4.2.11 Ensure SSH IgnoreRhosts is enabled (Automated)" "/etc/ssh/sshd_config.d/custom_config.conf" "IgnoreRhosts" "IgnoreRhosts yes"
update_config_option "4.2.15 Ensure only strong Key Exchange algorithms are used" "/etc/ssh/sshd_config.d/custom_config.conf" "KexAlgorithms" "KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256"
update_config_option "4.2.10 Ensure SSH PermitUserEnvironment is disabled" "/etc/ssh/sshd_config.d/custom_config.conf" "PermitUserEnvironment" "PermitUserEnvironment no"
update_config_option "4.2.9 Ensure SSH PermitEmptyPasswords is disabled" "/etc/ssh/sshd_config.d/custom_config.conf" "PermitEmptyPasswords" "PermitEmptyPasswords no"
update_config_option "4.2.7 Ensure SSH root login is disabled (Automated)" "/etc/ssh/sshd_config" "PermitRootLogin" "PermitRootLogin no"
update_config_option "4.2.8 Ensure SSH HostbasedAuthentication is disabled" "/etc/ssh/sshd_config.d/custom_config.conf" "HostbasedAuthentication" "HostbasedAuthentication no"

}



#-----------------------------------------------------
# ----> 4.3 Configure privilege escalation <----
#-----------------------------------------------------

configure_privilege_escalation() {

echo "!---! 4.3 Configure privilege escalation !---!"

perform_package_option "5.3.1 Ensure sudo is installed (Automated))" "install" "sudo"
update_config_option "5.3.2 Ensure sudo commands use pty (Automated)" "/etc/sudoers.d/use_pty" "Defaults" "Defaults use_pty"
update_config_option "5.3.3 Ensure sudo log file exists (Automated)" "/etc/sudoers.d/use_pty" "Defaults logfile" "Defaults logfile=\"/var/log/sudo.log\""
# Below should be automated in the future!
perform_manual_command  "5.3.4 Ensure re-authentication for privilege escalation is not disabled globally (Automated)" "Remove any line with occurrences of NOPASSWD tags in the file /etc/sudoers and /etc/sudoers.d/*" "grep -r \"^[^#].*NOPASSWD\" /etc/sudoers*"
# Below should be automated in the future!
perform_manual_command  "5.3.4 Ensure users must provide password for privilege escalation (Automated)" "Remove any occurrences of !authenticate tags in the file(s) --> /etc/sudoers*" "grep -r \"^[^#].*\!authenticate\" /etc/sudoers*"
perform_command_option "5.3.5 Ensure access to the su command is restricted (Automated)" "groupadd sugroup"
update_config_option "5.3.5 Ensure access to the su command is restricted (Automated)" "/etc/pam.d/su" "auth required pam_wheel.so use_uid group=" "auth required pam_wheel.so use_uid group=sugroup"
perform_command_option "5.3.7 Ensure sudo authentication timeout is configured correctly(Automated)" "touch /etc/sudoers.d/sudo_auth_timeout ; echo 'Defaults env_reset, timestamp_timeout=10' >> /etc/sudoers.d/sudo_auth_timeout"

}



#-----------------------------------------------------
# ----> 4.4 Configure PAM <----
#-----------------------------------------------------

configure_pam() { 

echo "---- 4.4 Configure PAM ----"

update_config_option "4.3.7" "/etc/pam.d/su" "auth required pam_wheel.so use_uid group" "auth required pam_wheel.so use_uid group=sugroup"
perform_package_option "5.4.1 Ensure password creation requirements are configured" "install" "libpam-pwquality"
update_config_option "5.4.1 Ensure password creation requirements are configured" "/etc/security/pwquality.conf" "minlen" "minlen = 14"
update_config_option "5.4.1 Ensure password creation requirements are configured" "/etc/security/pwquality.conf" "minclass" "minclass = 4"
perform_package_option "Installing libpalm for next benchmark..." "install" "libpam-cap"
perform_command_option "5.4.2 Ensure lockout for failed password attempts is configured" "echo 'account required pam_faillock.so' >> /etc/pam.d/common-account ; cat << EOF >> /etc/security/faillock.conf
deny = 4
fail_interval = 900
unlock_time = 600
EOF
cat << EOF >> /etc/pam.d/common-auth
auth    required                        pam_faillock.so preauth
auth    [success=1 default=ignore]      pam_unix.so nullok
auth    [default=die]                   pam_faillock.so authfail
auth    sufficient                      pam_faillock.so authsucc
auth    requisite                       pam_deny.so
auth    required                        pam_permit.so
auth    optional                        pam_cap.so
EOF
echo 'account required                        pam_faillock.so' >> /etc/pam.d/common-account"
perform_command_option "5.4.3 Ensure password reuse is limited (Automated)" "sudo sed -i 's/password[[:space:]]*[success=1[[:space:]]*default=ignore][[:space:]]*pam_unix\.so[[:space:]]*obscure[[:space:]]*use_authtok[[:space:]]*try_first_pass[[:space:]]*\(sha512\|yescrypt\)/password [success=1 default=ignore] pam_unix.so obscure use_authtok try_first_pass remember=5/g' /etc/pam.d/common-password"
update_config_option "5.4.4 Ensure password hashing algorithm is up to date with the" "/etc/login.defs" "ENCRYPT_METHOD" "ENCRYPT_METHOD yescrypt"

}



#-----------------------------------------------------
# ----> 4.5 User Accounts and Environment <----
#-----------------------------------------------------

user_accounts_and_environment() {

echo "---- 4.5 User Accounts and Environment ---- "

update_config_option "5.5.1.1 Ensure minimum days between password changes is configured (Automated)" "/etc/login.defs" "PASS_MAX_DAYS" "PASS_MAX_DAYS 365"
update_config_option "5.5.1.2 Ensure password expiration is 365 days or less(Automated)" "/etc/login.defs" "PASS_MIN_DAYS" "PASS_MIN_DAYS 1"
update_config_option "5.5.1.3 Ensure password expiration warning days is 7 or more(Automated)" "/etc/login.defs" "PASS_WARN_AGE" "PASS_WARN_AGE 7"
perform_command_option "5.4.1.4 Ensure inactive password lock is 30 days or less (Automated)" "useradd -D -f 30"
perform_command_option "5.4.3 Ensure default group for the root account is GID 0 (Automated)" "usermod -g 0 root"
perform_command_option "5.4.4 Ensure default user umask is 027 or more restrictive (Automated)" "touch /etc/profile.d/set_umask.sh ; echo 'umask 027' >> touch /etc/profile.d/set_umask.sh"
perform_command_option "5.4.5 Ensure default user shell timeout is 900 seconds or less (Automated)" "readonly TMOUT=900 ; export TMOUT"
perform_manual_command "5.5.1.5 Ensure all users last password change date is in the past" "awk -F: '/^[^:]+:[^!*]/{print \$1}' /etc/shadow | while read -r usr; do change=\$(date -d \"\$(chage --list \$usr | grep '^Last password change' | cut -d: -f2 | grep -v 'never$')\" +%s); if [[  \"\$change\" -gt \"\$(date +%s)\" ]]; then echo \"User: \"\$usr\" last password change was \"\$(chage --list \$usr | grep '^Last password change' | cut -d: -f2)\"\"; else echo \"last password change for $usr OK\" ; fi; done"

}



#-----------------------------------------------------
# ----> System Maintenance <----
# ----> 6.1 System File Permissions <----
#-----------------------------------------------------

system_file_permission() {

echo " ---- 6.1 System File Permissions ----"

perform_command_option "6.1.2 Ensure permissions on /etc/passwd are configured (Automated)" "chown root:root /etc/passwd ; chmod u-x,go-wx /etc/passwd"
perform_command_option "6.1.3 Ensure permissions on /etc/passwd- are configured (Automated)" "chown root:root /etc/passwd- ; chmod u-x,go-rwx /etc/passwd-"
perform_command_option "6.1.4 Ensure permissions on /etc/group are configured (Automated)" "chown root:root /etc/group ; chmod 644 /etc/group"
perform_command_option "6.1.5 Ensure permissions on /etc/group- are configured (Automated)" "chown root:root /etc/group- ; chmod u-x,go-wx /etc/group-"
perform_command_option "6.1.6 Ensure permissions on /etc/shadow are configured (Automated)" "chown root:shadow /etc/shadow ; chmod o-rwx,g-wx /etc/shadow"
perform_command_option "6.1.7 Ensure permissions on /etc/shadow- are configured (Automated)" "chown root:shadow /etc/shadow- ; chmod u-x,go-rwx /etc/shadow-"
perform_command_option "6.1.8 Ensure permissions on /etc/gshadow- are configured (Automated)" "chown root:root /etc/gshadow- ; chmod u-x,g-wx,o-rwx /etc/gshadow-"
perform_command_option "6.1.9 Ensure permissions on /etc/gshadow are configured (Automated)" "chown root:shadow /etc/gshadow ; chmod o-rwx,g-wx /etc/gshadow"

# THESE SHOULD BE AUTOMATED IN THE FUTURE!....
perform_manual_command "6.1.10 Ensure no world writable files exist (Automated)" "If anything is returned from running remidation command, then: Removing write access for the \"other\" category ( chmod o-w <filename> ) is advisable" "df --local -P | awk '{if (NR!=1) print \$6}' | xargs -I '{}' find '{}' -xdev -type f -perm -0002"
perform_manual_command "6.1.11 Ensure no unowned files or directories exist (Automated)" "If anything is returned from running remidation command, then: Locate files that are owned by users or groups not listed in the system configuration files, and reset the ownership of these files to some active user on the system as appropriate. " "df --local -P | awk '{if (NR!=1) print \$6}' | xargs -I '{}' find '{}' -xdev -nouser"
perform_manual_command "6.1.12 Ensure no ungrouped files or directories exist (Automated)" "If anything is returned from running remidation command, then: Locate files that are owned by users or groups not listed in the system configuration files, and reset the ownership of these files to some active user on the system as appropriate." "df --local -P | awk '{if (NR!=1) print \$6}' | xargs -I '{}' find '{}' -xdev -nogroup"
perform_manual_command "6.1.13 Audit SUID executables (Manual)" "If anything is returned from running remidation command, then: Ensure that no rogue SUID programs have been introduced into the system. Review the files returned by the action in the Audit section and confirm the integrity of these binaries." "df --local -P | awk '{if (NR!=1) print \$6}' | xargs -I '{}' find '{}' -xdev -type f -perm -4000"

}


#-----------------------------------------------------
# ----> 6.2 Local User and Group Settings <----
#-----------------------------------------------------

local_user_and_group_settings() {

echo "---- 6.2 Local User and Group Settings ----"
perform_manual_command "6.2.1 Ensure /etc/shadow password fields are not empty" "You can use this audit to verify no output is returned. Else use command to set a password for any users wihout a pasasword" "passwd -l <username>"
perform_command_option "6.2.4 Ensure shadow group is empty (Automated)" "for user in \$(awk -F: '(\$1==\"shadow\") {print \$NF}' /etc/group | awk -F: -v GID=\"\$(awk -F: '(\$1==\"shadow\") {print \$3}' /etc/group)\" '(\$4==GID) {print \$1}' /etc/passwd); do id \"\$user\" | grep -q \"shadow\" && sed -ri 's/(^shadow:[^:]*:[^:]*:)([^:]+\$)/\1/' /etc/group && read -p  \"Warning, user: \$user found in shadow file. Change their primary group to: \" new_group && usermod -g \"\$new_group\" \"\$user\"; done"
perform_command_option "6.2.5 Ensure no duplicate UIDs exist (Automated)" "if cut -f3 -d\":\" /etc/passwd | sort | uniq -d | grep -q .; then echo \"Duplicate UID found\"; [ \$? -eq 1 ]; else echo \"No Duplicate UID found\"; [ \$? -eq 0 ]; fi"
perform_command_option "6.2.6 Ensure no duplicate GIDs exist (Automated)" "if cut -d: -f3 /etc/group | sort | uniq -d | grep -q .; then echo \"Duplicate GID found\"; [ \$? -eq 1 ]; else echo \"No Duplicate GID found\"; [ \$? -eq 0 ]; fi"
perform_command_option "6.2.7 Ensure no duplicate user names exist (Automated)" "if cut -d: -f1 /etc/passwd | sort | uniq -d | grep -q .; then cut -d: -f1 /etc/passwd | sort | uniq -d | while read -r x; do echo \"Duplicate login name \$x in /etc/passwd\"; done && [ \$? -eq 0 ]; else echo \"No duplicate login name found\" && [ \$? -eq 0 ]; fi"
perform_command_option "6.2.8 Ensure no duplicate group names exist (Automated)" "if cut -d: -f1 /etc/group | sort | uniq -d | grep -q .; then cut -d: -f1 /etc/group | sort | uniq -d | while read -r x; do [ -z \"\$x\" ] && break ; echo \"Duplicate group name \$x in /etc/group\"; done && [ \$? -eq 1 ]; else echo \"No duplicate group name found\" && [ \$? -eq 0 ]; fi"
perform_command_option "6.2.9 Ensure root PATH Integrity (Automated)" "RPCV=\"\$(sudo -Hiu root env | grep '^PATH' | cut -d= -f2)\"; echo \"\$RPCV\" | grep -q \"::\" && echo \"root's path contains an empty directory (::)\"; echo \"\$RPCV\" | grep -q \":\$\" && echo \"root's path contains a trailing (:)\" ; for x in \$(echo \"\$RPCV\" | tr \":\" \" \"); do if [ -d \"\$x\" ]; then ls -ldH \"\$x\" | awk '\$9 == \".\" {print \"PATH contains current working directory (.)\"} \$3 != \"root\" {print \$9, \"is not owned by root\"} substr(\$1,6,1) != \"-\" {print \$9, \"is group writable\"} substr(\$1,9,1) != \"-\" {print \$9, \"is world writable\"}'; else echo \"\$x is not a directory\"; fi done ; echo \"Please Correct or justify any items discovered\""
perform_command_option "6.2.10 Ensure root is the only UID 0 account (Automated)" "awk -F: '(\$3 == 0) { print \$1; if (\$1 != \"root\") found = 1 } END { if (found) { print \"Other users with UID 0 found. Please make sure ONLY root has 0 as UID\"; exit 1 } }' /etc/passwd"
perform_command_option "6.2.11 Ensure local interactive user home directories exist" "valid_shells=\"^(\$(sed -rn '/^\\//{s,/,\\\\\\\\/,g;p}' /etc/shells | paste -s -d '|' -))\$\"; awk -v pat=\"\$valid_shells\" -F: '\$(NF) ~ pat { print \$1 \" \" \$(NF-1) }' /etc/passwd | while read -r user home; do if [ ! -d \"\$home\" ]; then echo -e \"\n- User \"\$user\" home directory \"\$home\" doesn't exist\n- creating home directory \"\$home\"\n\"; mkdir \"\$home\"; chmod g-w,o-wrx \"\$home\"; chown \"\$user\" \"\$home\"; fi; done"
perform_command_option "6.2.12 Ensure local interactive users own their home directories" "output=\"\"; valid_shells=\"^(\$(sed -rn '/^\\//{s,/,\\\\\\\\/,g;p}' /etc/shells | paste -s -d '|' -))\$\"; awk -v pat=\"\$valid_shells\" -F: '\$(NF) ~ pat { print \$1 \" \" \$(NF-1) }' /etc/passwd | while read -r user home; do owner=\"\$(stat -L -c \"%U\" \"\$home\")\"; if [ \"\$owner\" != \"\$user\" ]; then echo -e \"\n- User \"\$user\" home directory \"\$home\" is owned by user \"\$owner\"\n - changing ownership to \"\$user\"\n\"; chown \"\$user\" \"\$home\"; fi; done"
perform_command_option "6.2.13 Ensure local interactive user home directories are mode750 or more restrictive (Automated)" "perm_mask='0027'; maxperm=\"\$(printf '%o' \$((0777 & ~\$perm_mask)))\"; valid_shells=\"^(\$(sed -rn '/^\\//{s,/,\\\\\\\\/,g;p}' /etc/shells | paste -s -d '|' -))\$\"; awk -v pat=\"\$valid_shells\" -F: '\$(NF) ~ pat { print \$1 \" \" \$(NF-1) }' /etc/passwd | (while read -r user home; do mode=\$(stat -L -c '%#a' \"\$home\"); if [ \$(( \$mode & \$perm_mask )) -gt 0 ]; then echo -e \"- modifying User \$user home directory: \"\$home\"\\n- removing excessive permissions from current mode of \"\$mode\"\"; chmod g-w,o-rwx \"\$home\"; fi; done)"
perform_command_option "6.2.14 Ensure no local interactive user has .netrc files" "perm_mask='0177';valid_shells=\"^(\$(sed -rn '/^\\//{s,/,\\\\\\\\/,g;p}' /etc/shells | paste -s -d '|' -))\$\"; awk -v pat=\"\$valid_shells\" -F: '\$(NF) ~ pat { print \$1 \" \" \$(NF-1) }' /etc/passwd | while read -r user home; do if [ -f \"\$home/.netrc\" ]; then echo -e \"\\n- User \"\$user\" file: \"\$home/.netrc\" exists\\n - removing file: \"\$home/.netrc\"\\n\"; rm -f \"\$home/.netrc\"; fi; done"
perform_command_option "6.2.15 Ensure no local interactive user has .forward files" "output=\"\"; fname=\".forward\"; valid_shells=\"^(\$(sed -rn '/^\\//{s,/,\\\\\\\\/,g;p}' /etc/shells | paste -s -d '|' -))\$\"; awk -v pat=\"\$valid_shells\" -F: '\$(NF) ~ pat { print \$1 \" \" \$(NF-1) }' /etc/passwd | while read -r user home; do if [ -f \"\$home/\$fname\" ]; then echo -e \"\$output\n- User \"\$user\" file: \"\$home/\$fname\" exists\n- removing file: \"\$home/\$fname\"\n\"; rm -f \"\$home/\$fname\"; fi; done"
perform_command_option "6.2.16 Ensure no local interactive user has .rhosts files" "perm_mask='0177';valid_shells=\"^(\$(sed -rn '/^\\//{s,/,\\\\\\\\/,g;p}' /etc/shells | paste -s -d '|' -))\$\"; awk -v pat=\"\$valid_shells\" -F: '\$(NF) ~ pat { print \$1 \" \" \$(NF-1) }' /etc/passwd | while read -r user home; do if [ -f \"\$home/.rhosts\" ]; then echo -e \"\\n- User \"\$user\" file: \"\$home/.rhosts\" exists\\n - removing file: \"\$home/.rhosts\"\n\"; rm -f \"\$home/.rhosts\"; fi; done"
perform_command_option "6.2.17 Ensure local interactive user dot files are not group or" "perm_mask='0022';valid_shells=\"^(\$(sed -rn '/^\\//{s,/,\\\\\\\\/,g;p}' /etc/shells | paste -s -d '|' -))\$\"; awk -v pat=\"\$valid_shells\" -F: '\$(NF) ~ pat { print \$1 \" \" \$(NF-1) }' /etc/passwd | while read -r user home; do find \"\$home\" -type f -name '.*' | while read -r dfile; do mode=\$(stat -L -c '%#a' \"\$dfile\"); if [ \$(( \$mode & \$perm_mask )) -gt 0 ]; then echo -e \"\\n- Modifying User \"\$user\" file: \"\$dfile\"\n- removing group and other write permissions\"; chmod go-w \"\$dfile\"; fi; done; done"

}


#-----------------------------------------------------
# ----> Restart ssh <----
#-----------------------------------------------------

restart_services() {

echo "restarting all requried services"
perform_package_option "Restarting ssh....." "restart" "ssh"

}


#-----------------------------------------------------
# ----> Finish   the script <----
#-----------------------------------------------------

finish_script_message () {

echo
echo "----------------------------------------------------------"
echo "WARNING! before you logout of user, reboot or switch users, to change the manual benchmarks settings that you encountered doing script runtime!"
echo "When you are done, make sure to reboot your system"
echo "Script is now done! program will now close......"
echo "----------------------------------------------------------"
echo 

unset DEBIAN_FRONTEND




}

#-------------------------------------------------------------------------------------------
# ----> Select what part of CIS 18 (IG1) you want to select by comment/uncomment below <----
#-------------------------------------------------------------------------------------------

main() {

configure_software_and_patch_management 
secure_boot_settings
mandatory_access_control 
command_line_warning_banners 
gnome_display_manager 
special_purpose_services 
service_clients 
disable_unused_network_protocols_and_devices
configure_firewall_iptables
configure_auditing
configure_audit_rules
configure_auditd_file_access 
configure_journald
configure_remotelog_server_wazuh
filesytem_configuration
configure_timebased_jobs_schedulers
configure_ssh_server
configure_privilege_escalation
configure_pam
user_accounts_and_environment
system_file_permission
local_user_and_group_settings
restart_services
finish_script_message

}


#-----------------------------------------------------
# ----> Start the script <----
#-----------------------------------------------------


main
