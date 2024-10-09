# cis18 benchmarks ubuntu 22 and debian 11 IG1

Bash script developed for hardening ubuntu 22 and debian 11 according to CIS IG1 remidations only. Not audits.
It's function is only intended for one time use on a new server setup.


## Info regarding Hostbased Firewall, Remote Log Server, bootloader, Ipv4

**Firewall** this script is using IPtables. Not UFW or NFtables, they are removed according to CIS requirements, because IPtables was chosen as primary.

**Log server** this script is using Wazuh as remote log server [What is Wazuh ?](https://documentation.wazuh.com/current/getting-started/architecture.html)

**Bootloader** the script is using grub as default bootloader. It will create a password, that is required for changing boot paramters. But not required to boot the system for convenience.

**Ipv4** the script will only use ipv4 and disable ipv6.

**Systemlogs** Journald is used for systemlogs. Not Ryslogs.


## Prerequisites before running the script

**Partitions**

If you wish having seperate partitions according to CIS 18 IG1, you must create these during installation of server. It would be a good idea to do while isntalling debian 11 or Ubuntu 22. Research and implement sizes according to your own server requirements:

- /var
- /var/tmp
- /var/log
- /var/log/audit
- /tmp
- /
- /home

**Prepare firewall rules**

I have made a iptables_rules.txt file with some default rules for cis recommendations. Correct it to your usecase, but make sure it's according to recommendations at the same time.

**Chosing what benchmarks to run**

At the end of the script there is a main function calling the other functions. You can pick and decide what benchmarks you want according to those. Lets say you do not wish to use to use Wazuh because you dont have a Wazuh server, comment the function call out. Then it will be your own responsibilty to setup this part yourself. Same goes for the rest. 
By default everything is set to run.

**Privileges needed to run**

Run script as sudo

**Download the benchmarks pdf from CIS (Ubuntu 22 server & Debian 11 server) before you run**

Helps you understand every implemention and why CIS recommend them for security


## Running the script on your Ubuntu/Debian server

```bash
git clone https://github.com/ulrik-vj/cis18-benchmarks-ubuntu-debian-ig1.git
cd cis18-benchmarks-ubuntu-debian-ig1
sudo chmod +x cis_ig1_hardening.sh
sudo ./cis_ig1_hardening.sh
```

## License

[GNU General Public License v3.0](LICENSE)
