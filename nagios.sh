#!/usr/bin/env bash
#-----------------------------------------------------------------------------#
# Author: Linfeng Zhong (Fred)
# 2021-Nov-28 [Initial Version] - Shell Script for Nagios server / client
#-----------------------------------------------------------------------------#
#================== RHEL 7/8 | CentOS 7/8 | Rocky Linux 8 ====================#
#================== Debian | Armbian | Ubuntu | OpenWrt   ====================#
#-----------------------------------------------------------------------------#
# 初始化全局变量
#-----------------------------------------------------------------------------#
export LANG=en_US.UTF-8
function inital_smart_tool() {
	# default Host
	defaultHost="pogo.dalian.ml"
	# default UUID
	defaultUUID="d8206743-b292-43d1-8200-5606238a5abb"
	# default Nagios server ip
	nagiosHostIP="192.168.1.10"
	# 随机路径
	customPath="rfda1334sfpmhd"

	# 自定义服务数组
	# array_service_description=("Network" "CPU" "Disk usage" "Memory" "Total procedures" "SSH" "Service v2ray" "Service xray" "Service trojan.go" "Service nginx" "Service httpd" "Service v2-ui" "Service x-ui" "Service webmin" "Service docker" "Service nrpe" "Service node_exporter" "HTTPS" "Certificate" "TCP 5666" "TCP 7080" "TCP 8080" "TCP 8443" "TCP 9100" "TCP 10000" )
	# array_check_command=("check_eth" "check_cpu_stats" "check_disk" "check_mem" "check_total_procs" "check_ssh" "check_v2ray" "check_xray" "check_trojan.go" "check_nginx" "check_httpd" "check_v2_ui" "check_x_ui" "check_webmin" "check_docker" "check_nrpe" "check_node_exporter" "check_http" "check_certificate_expires" "check_port_5666" "check_port_7080" "check_port_8080" "check_port_8443" "check_port_9100" "check_port_10000" )

	# array_service_description=("Network sent" "Network receive" "CPU" "Disk" "Memory" "SSH" "Service xray" "Service nginx" "Service webmin" "Service nrpe" "Service ncpa" "HTTP" "Certificate" "TCP 443 nginx xray" "TCP 5666 nrpe" "TCP 5693 ncpa" "TCP 9100 node exporter" "TCP 9999 webmin" "Service node exporter" "Total process" )
	# array_check_command=("check_ncpa_interface_sent" "check_ncpa_interface_receive" "check_ncpa_cpu" "check_ncpa_disk" "check_ncpa_memory" "check_ssh" "check_ncpa_service_xray" "check_ncpa_service_nginx" "check_ncpa_service_webmin" "check_ncpa_service_nrpe" "check_ncpa_service_ncpa_listener" "check_http" "check_certificate_expires" "check_port_443" "check_port_5666" "check_port_5693" "check_port_9100" "check_port_9999" "check_ncpa_service_node_exporter" "check_ncpa_processes")

    array_service_description=("Network sent" "Network receive" "CPU" "Disk" "Memory" "SSH" "Service xray" "Service nginx" "Service ncpa" "Http" "Certificate" "TCP 443 nginx xray" "TCP 5693 ncpa" "Total process" )
    array_check_command=("check_ncpa_interface_sent" "check_ncpa_interface_receive" "check_ncpa_cpu" "check_ncpa_disk" "check_ncpa_memory" "check_ssh" "check_ncpa_service_xray" "check_ncpa_service_nginx" "check_ncpa_service_ncpa_listener" "check_http" "check_certificate_expires" "check_port_443" "check_port_5693" "check_ncpa_processes")

	#定义变量
	# WORKDIR="/root/git/toolbox/Docker/docker-compose/${currentHost}/"
	SmartToolDir="/root/git/toolbox/Shell"
	# WORKDIR="/etc/fuckGFW/docker/${currentHost}/"
	# LOGDIR="/root/git/logserver/${currentHost}/"
	GITHUB_REPO_TOOLBOX="/root/git/toolbox"
	GITHUB_REPO_LOGSERVER="/root/git/logserver"
	EMAIL="fred.zhong@outlook.com"
	myDate=date
	fallbacksList=

	#fonts color 字体颜色配置
	Red="\033[31m"
	Yellow="\033[33m"
	Blue="\033[36m"
	Green="\033[32m"
	RedBG="\033[41;37m"
	GreenBG="\033[42;37m"
	Magenta="\033[31m"
	Font="\033[0m"
	# Notification information 通知信息
	# Info="${Green}[Message信息]${Font}"
	Start="${Yellow}[Start开始]${Font}"
	Info="${Magenta}[Info信息]${Font}"
	OK="${Green}[OK正常]${Font}"
	Error="${Red}[ERROR错误]${Font}"
	DONE="${Green}[Done完成]${Font}"
	
	installType='yum -y install'
	removeType='yum -y remove'
	upgrade="yum -y update"
	echoType='echo -e'

	# current Domain
	currentHost=
	# UUID
	currentUUID=
	# CDN节点的address
	add=
	# 安装总进度
	totalProgress=1
	# 1.xray-core安装
	# 2.v2ray-core 安装
	# 3.v2ray-core[xtls] 安装
	coreInstallType=
	# 核心安装path
	# coreInstallPath=
	# v2ctl Path
	ctlPath=
	# 1.全部安装
	# 2.个性化安装
	# v2rayAgentInstallType=
	# 当前的个性化安装方式 01234
	currentInstallProtocolType=
	# 选择的个性化安装方式
	selectCustomInstallType=
	# v2ray-core、xray-core配置文件的路径
	configPath=
	# 配置文件的path
	currentPath=
	# 安装时选择的core类型
	selectCoreType=
	# 默认core版本
	v2rayCoreVersion=

	# centos version
	centosVersion=
	# pingIPv6 pingIPv4
	# pingIPv4=
	pingIPv6=
	# 集成更新证书逻辑不再使用单独的脚本--RenewTLS
	renewTLS=$1

	currentIP=$(curl -s https://ipinfo.io/ip)

	if [[ -f "$HOME/.currentUUID" ]]; then
		currentUUID=$(cat $HOME/.currentUUID)
	else
		currentUUID=${defaultUUID}
	fi

	release=
}
#-----------------------------------------------------------------------------#
#打印Start
#-----------------------------------------------------------------------------#
function print_start() {
	echo -e "${Start} ${Blue} $1 ${Font}"
}
#-----------------------------------------------------------------------------#
#打印Info
#-----------------------------------------------------------------------------#
function print_info() {
	echo -e "${Info} ${Blue}  $1 ${Font}"
}
#-----------------------------------------------------------------------------#
#打印OK
#-----------------------------------------------------------------------------#
function print_ok() {
	echo -e "${OK} ${Blue} $1 ${Font}"
}
#-----------------------------------------------------------------------------#
#打印Done
#-----------------------------------------------------------------------------#
function print_done() {
	echo -e "${DONE} ${Blue}  $1 ${Font}"
}
#-----------------------------------------------------------------------------#
#打印Error
#-----------------------------------------------------------------------------#
function print_error() {
	echo -e "${ERROR} ${RedBG} $1 ${Font}"
}
#-----------------------------------------------------------------------------#
#判定 成功 or 失败
#-----------------------------------------------------------------------------#
function print_complete() {
	if [[ 0 -eq $? ]]; then
		print_done "$1" 
		#echoContent magenta "[Done完成]"
	else
		print_error "$1 <--- 失败"
		exit 1
	fi
}
#-----------------------------------------------------------------------------#
# 输出带颜色内容 字体颜色配置
#-----------------------------------------------------------------------------#
function echoContent() {
	case $1 in
		# 红色
	"red")
		# shellcheck disable=SC2154
		${echoType} "\033[31m${printN}$2 \033[0m"
		;;
		# 天蓝色
	"skyBlue")
		${echoType} "\033[1;36m${printN}$2 \033[0m"
		;;
		# 绿色
	"green")
		${echoType} "\033[32m${printN}$2 \033[0m"
		;;
		# 白色
	"white")
		${echoType} "\033[37m${printN}$2 \033[0m"
		;;
		# 洋红
	"magenta")
		${echoType} "\033[31m${printN}$2 \033[0m"
		;;
		# 黄色
	"yellow")
		${echoType} "\033[33m${printN}$2 \033[0m"
		;;
	esac
}
#-----------------------------------------------------------------------------#
# 清理屏幕
#-----------------------------------------------------------------------------#
function cleanScreen() {
	clear
}
#-----------------------------------------------------------------------------#
# 设置 current Host Domain 
#-----------------------------------------------------------------------------#
function set_current_host_domain {
	print_start "设置 current Host Domain "
	if [[ -f "$HOME/.myHostDomain" ]]; then
		print_error "已经设置服务器域名，无需重复设置！"
		currentHost=$(cat $HOME/.myHostDomain)
	else
		print_info "初始化 SmartTool v3 "
		print_info "$HOME/.myHostDomain "
		read -r -p "请设置服务器域名：" inputHostName
			if [ $inputHostName ]; then
				print_info "----- 服务器域名 ----"
				print_error "${inputHostName}"
				print_info "----- 服务器域名 ----"
				echo "${inputHostName}" > $HOME/.myHostDomain
			else
				print_error "未输入域名，使用默认域名: ${defaultHost}"
				print_info "----- 默认服务器域名 ----"
				print_error "${defaultHost}"
				print_info "----- 默认服务器域名 ----"
				echo "${defaultHost}" > $HOME/.myHostDomain
			fi
		currentHost=$(cat $HOME/.myHostDomain)
	fi
	WORKDIR="/etc/fuckGFW/docker/${currentHost}/"
	LOGDIR="/root/git/logserver/${currentHost}/"
	print_complete "设置 current Host Domain "

# Change host name
	if [[ -f "/usr/bin/hostnamectl" ]]; then 
		hostnamectl set-hostname ${currentHost}
		hostnamectl status
	else
		rm -f /etc/hostname
		echo "${currentHost}" > /etc/hostname
		cat /etc/hostname
	fi

}
#-----------------------------------------------------------------------------#
# 检查系统
#-----------------------------------------------------------------------------#
function checkSystem() {
	if [[ -n $(find /etc -name "rocky-release") ]] || grep </proc/version -q -i "rockylinux"; then
		mkdir -p /etc/yum.repos.d
		if [[ -f "/etc/rocky-release" ]];then
			centosVersion=$(rpm -q rocky-release | awk -F "[-]" '{print $3}' | awk -F "[.]" '{print $1}')
			if [[ -z "${centosVersion}" ]] && grep </etc/rocky-release "version 8"; then
				centosVersion=8
			fi
		fi
		release="rocky"
		installType='yum -y install'
		removeType='yum -y remove'
		upgrade="yum update -y --skip-broken"
		echoContent white "Rocky Linux release 8.4 (Green Obsidian)"

	elif [[ -n $(find /etc -name "redhat-release") ]] || grep </proc/version -q -i "centos"; then
		mkdir -p /etc/yum.repos.d
		if [[ -f "/etc/centos-release" ]];then
			centosVersion=$(rpm -q centos-release | awk -F "[-]" '{print $3}' | awk -F "[.]" '{print $1}')
		#	if [[ -z "${centosVersion}" ]] && grep </etc/centos-release "release 8"; then
		#		centosVersion=8
		#	fi
		fi
		release="centos"
		installType='yum -y install'
		removeType='yum -y remove'
		upgrade="yum update -y --skip-broken"
		echoContent white "CentOS 8.4"

	elif grep </etc/issue -q -i "debian" && [[ -f "/etc/issue" ]] || grep </etc/issue -q -i "debian" && [[ -f "/proc/version" ]]; then
		if grep </etc/issue -i "8"; then
			debianVersion=8
		fi
		release="debian"
		installType='apt -y install'
		upgrade="apt update -y"
		removeType='apt -y autoremove'
		echoContent white "debian"

	elif grep </etc/issue -q -i "ubuntu" && [[ -f "/etc/issue" ]] || grep </etc/issue -q -i "ubuntu" && [[ -f "/proc/version" ]]; then
		release="ubuntu"
		installType='apt-get -y install'
		upgrade="apt-get update -y"
		removeType='apt-get --purge remove'
		echoContent white "ubuntu"
	fi

	if [[ -z ${release} ]]; then
		echo "本脚本不支持此系统，请将下方日志反馈给开发者"
		cat /etc/issue
		cat /etc/os-release
		cat /proc/version
		exit 0
	fi
}
#-----------------------------------------------------------------------------#
# 安装 apache - httpd | apache 2
#-----------------------------------------------------------------------------#
function install_apache_httpd {

	if [ release = "rocky" ] || [ release = "centos" ] then

		print_start "安装 apache httpd, 并设置端口：8080"
		if [[ -d "/etc/httpd" ]]; then
			print_error "apache httpd已安装，无需重复操作！"
		else
			print_info "安装进行中ing "
			yum -y install httpd >/dev/null 2>&1
			# /etc/httpd/conf/httpd.conf
			if cat /etc/httpd/conf/httpd.conf | grep "Listen 8080" ; then
				print_error "已经设置端口：8080，无需重复设置！"
			else
				sed -i 's!Listen 80!Listen 8080!g' /etc/httpd/conf/httpd.conf
			fi
			# systemctl reload httpd
			systemctl enable httpd
			systemctl restart httpd
		fi
		print_complete "安装 apache httpd, 并设置端口：8080"

	else
		print_start "安装 apache2, 并设置端口：8080"
		if [[ -d "/etc/apache2" ]]; then
			print_error "apache2 已安装，无需重复操作！"
		else
			print_info "安装进行中ing "
			installType apache2 >/dev/null 2>&1
			# /etc/apache2/apache2.conf
			# /etc/apache2/sites-enabled/nagios.conf
			# /etc/apache2/ports.conf
			# /etc/apache2/sites-enabled/000-default.conf
			if cat /etc/apache2/ports.conf | grep "Listen 8080" ; then
				print_error "已经设置端口：8080，无需重复设置！"
			else
				sed -i 's!Listen 80!Listen 8080!g' /etc/apache2/ports.conf
			fi
			# systemctl reload httpd
			systemctl enable apache2
			systemctl restart apache2
		fi
		print_complete "安装 apache2, 并设置端口：8080"
	fi

}
#-----------------------------------------------------------------------------#
# 激活 apache httpd SSL
function enable_apache_httpd_ssl {
	print_start "激活 apache httpd SSL - Port: 8443"
	if [[ -f "/etc/httpd/conf.d/ssl.conf" ]]; then
		print_error "apache httpd SSL已经设置，无需重复操作！"
	else
		print_info "Step 1: 安装ssl认证模块 "
		yum -y install mod_ssl >/dev/null 2>&1
		print_info "Step 2: 编辑 /etc/httpd/conf.d/ssl.conf"
		cat <<EOF >/etc/httpd/conf.d/ssl.conf
Listen 8443 https

SSLPassPhraseDialog exec:/usr/libexec/httpd-ssl-pass-dialog
SSLSessionCache         shmcb:/run/httpd/sslcache(512000)
SSLSessionCacheTimeout  300
SSLCryptoDevice builtin

<VirtualHost _default_:8443>

ErrorLog logs/ssl_error_log
TransferLog logs/ssl_access_log
LogLevel warn

SSLEngine on

#SSLProtocol all -SSLv3
#SSLProxyProtocol all -SSLv3

SSLHonorCipherOrder on

SSLCipherSuite PROFILE=SYSTEM
SSLProxyCipherSuite PROFILE=SYSTEM

SSLCertificateFile /etc/fuckGFW/tls/${currentHost}.cer
SSLCertificateKeyFile /etc/fuckGFW/tls/${currentHost}.key
SSLCertificateChainFile /etc/fuckGFW/tls/fullchain.cer
SSLCACertificateFile /etc/fuckGFW/tls/ca.cer

<FilesMatch "\.(cgi|shtml|phtml|php)$">
    SSLOptions +StdEnvVars
</FilesMatch>
<Directory "/var/www/cgi-bin">
    SSLOptions +StdEnvVars
</Directory>

BrowserMatch "MSIE [2-5]" \
         nokeepalive ssl-unclean-shutdown \
         downgrade-1.0 force-response-1.0

CustomLog logs/ssl_request_log \
          "%t %h %{SSL_PROTOCOL}x %{SSL_CIPHER}x \"%r\" %b"

</VirtualHost>
EOF
		print_info "Step 3: 编辑 /etc/httpd/conf/httpd.conf "
		if cat /etc/httpd/conf/httpd.conf | grep "# 2021 July 21st" ; then
			print_error "已经设置跳转https，无需重复！"
		else
			cat <<EOF >>/etc/httpd/conf/httpd.conf
# 2021 July 21st
RewriteEngine On
RewriteCond %{HTTPS} off
RewriteRule (.*) https://%{HTTP_HOST}%{REQUEST_URI}
EOF
		fi
		print_info "Step 4: 重新启动 httpd.service "
		#重启http服务
		systemctl restart httpd.service
		#查看状态
		# systemctl status httpd.service
		print_info "Nagio 访问地址 https://${currentHost}:8443/nagios"
		print_info "Nagio 用户名：nagiosadmin"
		print_info "Nagio 密码：xxxxxx"
	fi
	print_complete "激活 apache httpd SSL - Port: 8443 "
}
#-----------------------------------------------------------------------------#
# 定制 Nagios Server Check MyServers Folder
function customize_nagios_server_check_myservers_folder {
	print_info "Step 1: Nagios 自定义文件夹 /usr/local/nagios/etc/objects/myservers "
	mkdir -p /usr/local/nagios/etc/objects/myservers
	chown nagios:nagios /usr/local/nagios/etc/objects/myservers
	chmod 777 /usr/local/nagios/etc/objects/myservers
}
#-----------------------------------------------------------------------------#
# 定制 Nagios Server Nagios.cfg
function customize_nagios_server_nagios_cfg {
	print_info "Step 2-1: Nagios 主配置文件集 /usr/local/nagios/etc/nagios.cfg"
	if [[ ! -f "/usr/local/nagios/etc/nagios.cfg" ]]; then
		print_error "Nagios 主配置文件不存在，请确认是否正确安装Nagios core！"
		exit 0
	else
		if cat /usr/local/nagios/etc/nagios.cfg | grep "cfg_dir=/usr/local/nagios/etc/objects/myservers" >/dev/null; then
   			print_error "nagios.cfg 已定制过，无需重复操作！"
		else
			# 注释掉内容
			sed -i 's!cfg_file=/usr/local/nagios/etc/objects/localhost.cfg!#cfg_file=/usr/local/nagios/etc/objects/localhost.cfg!g' /usr/local/nagios/etc/nagios.cfg
			# 添加myserver文件夹
			sed -i 's!#cfg_dir=/usr/local/nagios/etc/servers!cfg_dir=/usr/local/nagios/etc/objects/myservers!g' /usr/local/nagios/etc/nagios.cfg
		fi
	fi

 	print_info "Step 2-2: Nagios 主配置通讯录 /usr/local/nagios/etc/objects/contacts.cfg"
	if [[ ! -f "/usr/local/nagios/etc/objects/contacts.cfg" ]]; then
		print_error "Nagios 通讯录文件不存在，请确认是否正确安装Nagios core！"
		exit 0
	else
		if cat /usr/local/nagios/etc/objects/contacts.cfg | grep "nagios@localhost" >/dev/null; then
			read -r -p "请输入Nagios Admin 邮件地址 : " NagiosAdminMail
			if [ $NagiosAdminMail ]; then
				sed -i 's!nagios@localhost!'"$NagiosAdminMail"'!g' /usr/local/nagios/etc/objects/contacts.cfg
			else
				print_info "未检测到输入邮件地址！"
			fi
		else
   			print_error "contacts.cfg 已定制过，无需重复操作！"
		fi
	fi

  	print_info "Step 2-3: Nagios 主配置时间段 /usr/local/nagios/etc/objects/timeperiods.cfg"
	print_info "Step 2-4: Nagios 主配置命令集 /usr/local/nagios/etc/objects/commands.cfg"
	print_info "Step 2-5: Nagios 主配置模版集 /usr/local/nagios/etc/objects/templates.cfg"
}
#-----------------------------------------------------------------------------#
# 定制 Nagios Server Myservers
#-----------------------------------------------------------------------------#
# 定制 Nagios Server Myservers two
#-----------------------------------------------------------------------------#
# 定制 Nagios Server Myservers Three
function customize_nagios_server_myservers_three {
	print_info "Step 3: Nagios 自定义文件夹 独立服务器配置文件"

	# NagiosClientDomain1
	# NagiosClientIP1
	local array_service_and_command_index=0
	local servicexx
	local temp_array_service_description
	local temp_array_check_command
	local temp_array_check_command1

	read -r -p "请输入Nagios client address : " NagiosClientDomain1
	if [ $NagiosClientDomain1 ]; then
		print_info "Step 3-1: 使用输入地址: ${NagiosClientDomain1}"
	else
		print_error "Step 3-1: 未检测到输入，使用默认地址: ${currentHost}"
		NagiosClientDomain1=${currentHost}
	fi
	
	NagiosClientIP1=$(ping ${NagiosClientDomain1} -c 1 | sed '1{s/[^(]*(//;s/).*//;q}')
	print_info "Step 3-2: 输入的服务器IP地址: \c"
	echoContent white "${NagiosClientIP1}"

	print_info "Step 3-3: 独立服务器配置文件 /usr/local/nagios/etc/objects/myservers/${NagiosClientDomain1}.cfg"
	cat <<EOF > /usr/local/nagios/etc/objects/myservers/${NagiosClientDomain1}.cfg
# Define a host for the remote machine
define host {
    host_name                       $NagiosClientDomain1
    alias                           $NagiosClientDomain1
    address                         $NagiosClientIP1
    notifications_enabled           1                       ; Host notifications are enabled
    event_handler_enabled           1                       ; Host event handler is enabled
    flap_detection_enabled          1                       ; Flap detection is enabled
    process_perf_data               1                       ; Process performance data
    retain_status_information       1                       ; Retain status information across program restarts
    retain_nonstatus_information    1                       ; Retain non-status information across program restarts
    check_period                    24x7                    ; By default, Linux hosts are checked round the clock
    check_interval                  5                       ; Actively check the host every 5 minutes
    retry_interval                  1                       ; Schedule host check retries at 1 minute intervals
    max_check_attempts              10                      ; Check each Linux host 10 times (max)
    check_command                   check-host-alive        ; Default command to check Linux hosts
    notification_period             24x7                    ; Send host notifications at any time 24x7 or workhours
    notification_interval           120                     ; Resend notifications every 2 hours
    notification_options            d,u,r                   ; Only send notifications for specific host states
                                                            ; d = send notifications on a DOWN state
                                                            ; u = send notifications on an UNREACHABLE state
                                                            ; r = send notifications on recoveries (OK state)
                                                            ; f = send notifications when the host starts and stops flapping
                                                            ; s = send notifications when scheduled downtime starts and ends
                                                            ; n = none
                                                            ; If you do not specify any notification options, Nagios will assume that you want notifications to be sent out for all possible states. 
    contacts                        nagiosadmin             ; This is a list of the short names of the contacts that should be notified whenever there are problems (or recoveries) with this host. Multiple contacts should be separated by commas.
                                                            ; Useful if you want notifications to go to just a few people and don't want to configure contact groups. You must specify at least one contact or contact group in each host definition.
    contact_groups                  admins                  ; Notifications get sent to the admins by default
}
EOF
	for servicexx in "${array_service_description[@]}"
	do
		temp_array_service_description=${array_service_description[array_service_and_command_index]}
		temp_array_check_command=${array_check_command[array_service_and_command_index]}

		if [[ "$temp_array_check_command" != "check_ssh" && "$temp_array_check_command" != "check_certificate_expires" && "$temp_array_check_command" != "check_ssl_certificate" && "$temp_array_check_command" != "check_http" && "$temp_array_check_command" != "check_port_5666" && "$temp_array_check_command" != "check_port_7080" && "$temp_array_check_command" != "check_port_8080" && "$temp_array_check_command" != "check_port_8443" && "$temp_array_check_command" != "check_port_9100" && "$temp_array_check_command" != "check_port_10000" && "$temp_array_check_command" != "check_ncpa_processes" ]]; then
			temp_array_check_command1="check_nrpe!"$temp_array_check_command
		else
			temp_array_check_command1=$temp_array_check_command
		fi
		cat <<EOF >> /usr/local/nagios/etc/objects/myservers/${NagiosClientDomain1}.cfg
# Define a service to check $temp_array_service_description on the remote machine.
define service {
    use                     generic-service
    host_name               $NagiosClientDomain1
    service_description     $temp_array_service_description
    check_command           $temp_array_check_command1
}
EOF
		let array_service_and_command_index++
	done

	chown nagios:nagios /usr/local/nagios/etc/objects/myservers/${NagiosClientDomain1}.cfg
	chmod 777 /usr/local/nagios/etc/objects/myservers/${NagiosClientDomain1}.cfg

	# cat /usr/local/nagios/etc/objects/myservers/${NagiosClientDomain1}.cfg

}
#-----------------------------------------------------------------------------#
# 定制 Nagios Server Host
function customize_nagios_server_myservers_host {
	# print_info "Step 3: Nagios 自定义文件夹 独立服务器配置文件"
	# NagiosClientDomain1
	# NagiosClientIP1

	read -r -p "请输入Nagios 被监控主机域名: " NagiosClientDomain1
	if [ $NagiosClientDomain1 ]; then
		print_info "被监控主机域名: \c"
		echoContent white "${NagiosClientDomain1}"
	else
		print_error "未检测到输入，使用默认域名: ${currentHost}"
		NagiosClientDomain1=${currentHost}
	fi
	
	NagiosClientIP1=$(ping ${NagiosClientDomain1} -c 1 | sed '1{s/[^(]*(//;s/).*//;q}')
	print_info "被监控主机IP地址: \c"
	echoContent white "${NagiosClientIP1}"

	print_info "Step 3: Nagios 自定义服务器 /usr/local/nagios/etc/objects/myservers/${NagiosClientDomain1}.cfg"
	cat <<EOF > /usr/local/nagios/etc/objects/myservers/${NagiosClientDomain1}.cfg
# Define a host for the remote machine
define host {
    host_name                       $NagiosClientDomain1
    alias                           $NagiosClientDomain1
    address                         $NagiosClientIP1
    notifications_enabled           1                       ; Host notifications are enabled
    event_handler_enabled           1                       ; Host event handler is enabled
    flap_detection_enabled          1                       ; Flap detection is enabled
    process_perf_data               1                       ; Process performance data
    retain_status_information       1                       ; Retain status information across program restarts
    retain_nonstatus_information    1                       ; Retain non-status information across program restarts
    check_period                    24x7                    ; By default, Linux hosts are checked round the clock
    check_interval                  5                       ; Actively check the host every 5 minutes
    retry_interval                  1                       ; Schedule host check retries at 1 minute intervals
    max_check_attempts              10                      ; Check each Linux host 10 times (max)
    check_command                   check-host-alive        ; Default command to check Linux hosts
    notification_period             24x7                    ; Send host notifications at any time 24x7 or workhours
    notification_interval           120                     ; Resend notifications every 2 hours
    notification_options            d,u,r                   ; Only send notifications for specific host states
                                                            ; d = send notifications on a DOWN state
                                                            ; u = send notifications on an UNREACHABLE state
                                                            ; r = send notifications on recoveries (OK state)
                                                            ; f = send notifications when the host starts and stops flapping
                                                            ; s = send notifications when scheduled downtime starts and ends
                                                            ; n = none
                                                            ; If you do not specify any notification options, Nagios will assume that you want notifications to be sent out for all possible states. 
    contacts                        nagiosadmin             ; This is a list of the short names of the contacts that should be notified whenever there are problems (or recoveries) with this host. Multiple contacts should be separated by commas.
                                                            ; Useful if you want notifications to go to just a few people and don't want to configure contact groups. You must specify at least one contact or contact group in each host definition.
    contact_groups                  admins                  ; Notifications get sent to the admins by default
}

EOF
	chown nagios:nagios /usr/local/nagios/etc/objects/myservers/${NagiosClientDomain1}.cfg
	chmod 777 /usr/local/nagios/etc/objects/myservers/${NagiosClientDomain1}.cfg

	if [[ "${NagiosClientDomain1}" == "k8s-master.cf" ]] ; then

		local array_service_description_master=("Service docker" "Service x-ui" "Service nagios" "Service httpd" "TCP 7080 nginx" "TCP 7443 nginx" "TCP 8080 httpd" "TCP 8443 httpd")
		local array_check_command_master=("check_ncpa_service_docker" "check_ncpa_service_x-ui" "check_ncpa_service_nagios" "check_ncpa_service_httpd" "check_port_7080" "check_port_7443" "check_port_8080" "check_port_8443")
		local servicexx_master
		local array_service_and_command_index_master=0
		local temp_array_service_description_master
		local temp_array_check_command_master

		print_info "发现Master主控，开始进行额外配置"

		for servicexx_master in "${array_service_description_master[@]}"
		do

		temp_array_service_description_master=${array_service_description_master[array_service_and_command_index_master]}
		temp_array_check_command_master=${array_check_command_master[array_service_and_command_index_master]}

		cat <<EOF >> /usr/local/nagios/etc/objects/myservers/${NagiosClientDomain1}.cfg
# Define a service to check $temp_array_service_description_master on the remote machine.
define service {
    use                     normal-service
    host_name               $NagiosClientDomain1
    service_description     $temp_array_service_description_master
    check_command           $temp_array_check_command_master
}

EOF
		let array_service_and_command_index_master++
		done
	else
		print_info "未发现Master主控，无需额外配置"
	fi

}
#-----------------------------------------------------------------------------#
# 定制 Nagios Server Services
function customize_nagios_server_myservers_services {
	print_info "Step 4: Nagios 自定义服务集 /usr/local/nagios/etc/objects/myservers/services.cfg"
	cat <<EOF > /usr/local/nagios/etc/objects/myservers/services.cfg
define service {
    name                            normal-service          ; The 'name' of this service template
    active_checks_enabled           1                       ; Active service checks are enabled
    passive_checks_enabled          1                       ; Passive service checks are enabled/accepted
    parallelize_check               1                       ; Active service checks should be parallelized (disabling this can lead to major performance problems)
    obsess_over_service             1                       ; We should obsess over this service (if necessary)
    check_freshness                 0                       ; Default is to NOT check service 'freshness'
    notifications_enabled           1                       ; Service notifications are enabled
    event_handler_enabled           1                       ; Service event handler is enabled
    flap_detection_enabled          1                       ; Flap detection is enabled
    process_perf_data               1                       ; Process performance data
    retain_status_information       1                       ; Retain status information across program restarts
    retain_nonstatus_information    1                       ; Retain non-status information across program restarts
    is_volatile                     0                       ; The service is not volatile
    check_period                    24x7                    ; The service can be checked at any time of the day
    max_check_attempts              3                       ; Re-check the service up to 3 times in order to determine its final (hard) state
    check_interval                  10                      ; Check the service every 10 minutes under normal conditions
    retry_interval                  2                       ; Re-check the service every two minutes until a hard state can be determined
    contact_groups                  admins                  ; Notifications get sent out to everyone in the 'admins' group
    notification_options            w,u,c,r                 ; Send notifications about warning, unknown, critical, and recovery events
    notification_interval           60                      ; Re-notify about service problems every hour
    notification_period             24x7                    ; Notifications can be sent out at any time
    register                        0                       ; DON'T REGISTER THIS DEFINITION - ITS NOT A REAL SERVICE, JUST A TEMPLATE!
}
EOF

	local array_service_and_command_index=0
	local servicexx
	local temp_array_service_description
	local temp_array_check_command
	local temp_array_check_command1

	for servicexx in "${array_service_description[@]}"
	do
		temp_array_service_description=${array_service_description[array_service_and_command_index]}
		temp_array_check_command=${array_check_command[array_service_and_command_index]}

#		if [[ "$temp_array_check_command" != "check_ssh" && "$temp_array_check_command" != "check_certificate_expires" && "$temp_array_check_command" != "check_ssl_certificate" && "$temp_array_check_command" != "check_http" && "$temp_array_check_command" != "check_port_5666" && "$temp_array_check_command" != "check_port_5693" && "$temp_array_check_command" != "check_port_7080" && "$temp_array_check_command" != "check_port_8080" && "$temp_array_check_command" != "check_port_8443" && "$temp_array_check_command" != "check_port_9100" && "$temp_array_check_command" != "check_port_10000" && "$temp_array_check_command" != "check_ncpa_processes" && "$temp_array_check_command" != "check_ncpa_cpu" && "$temp_array_check_command" != "check_ncpa_memory" ]]; then
		if [[ "$temp_array_check_command" = "check_eth" || "$temp_array_check_command" = "check_disk" ]]; then
			temp_array_check_command1="check_nrpe!"$temp_array_check_command
		else
			temp_array_check_command1=$temp_array_check_command
		fi
		cat <<EOF >> /usr/local/nagios/etc/objects/myservers/services.cfg
# Define a service to check $temp_array_service_description on the remote machine.
define service {
    use                     normal-service
    hostgroup_name          Fuck GFW
    service_description     $temp_array_service_description
    check_command           $temp_array_check_command1
}
EOF
		let array_service_and_command_index++
	done
	chown nagios:nagios /usr/local/nagios/etc/objects/myservers/services.cfg
	chmod 777 /usr/local/nagios/etc/objects/myservers/services.cfg
}
#-----------------------------------------------------------------------------#
# 定制 Nagios Server Host Group
function customize_nagios_server_myservers_host_group {
	print_info "Step 5: Nagios 自定义主机组 /usr/local/nagios/etc/objects/myservers/host_group.cfg"

	# 读取文件名到数组
	local search_dir="/usr/local/nagios/etc/objects/myservers"
	for entry in $search_dir/*
	do
		if [ -f $entry ]; then
			arr=(${arr[*]} $entry)
		fi
	done

	local Myservers_Host_Group=$currentHost
	#if [[ -f "/usr/local/nagios/etc/objects/myservers/host_group.cfg" ]] && cat /usr/local/nagios/etc/objects/myservers/host_group.cfg | grep "# 2021 July 19th" >/dev/null; then
	#	print_error "host_group.cfg 已经配置过了！"
	#else
	# 遍历数组，生成myservers
		local myservers_index=0
		for i in ${arr[*]}
		do
		# 正则表达式 ${var##*/}  --> 左边算起的最后一个/字符左边的内容
		# print_info "${arr[myservers_index]##*/}"
		
		tmpMyservers_Host_Group=${arr[myservers_index]##*/}
		if [[ "${tmpMyservers_Host_Group}" == "host_group.cfg" ]] || [[ "${tmpMyservers_Host_Group}" == "service_group.cfg" ]] || [[ "${tmpMyservers_Host_Group}" == "mycommands.cfg" ]] || [[ "${tmpMyservers_Host_Group}" == "services.cfg" ]] || [[ "${tmpMyservers_Host_Group}" == "$currentHost"".cfg" ]] ; then
		#if [[ "${coreInstallType}" == "1" ]] && [[ -n $(pgrep -f xray/xray) ]]; then
			# skip
			# print_error "skip file"
			# echoContent white "${tmpMyservers_Host_Group}"
			let myservers_index++
		else
			Myservers_Host_Group=$Myservers_Host_Group","${tmpMyservers_Host_Group%.*}
			# print_info "$Myservers_Host_Group"
			let myservers_index++
		fi
		done

	# 写入文件
		cat <<EOF > /usr/local/nagios/etc/objects/myservers/host_group.cfg
# 2021 July 19th
define hostgroup{
	hostgroup_name  Fuck GFW
	alias           Fuck GFW
	members         $Myservers_Host_Group
	}
EOF

		chown nagios:nagios /usr/local/nagios/etc/objects/myservers/host_group.cfg
		chmod 777 /usr/local/nagios/etc/objects/myservers/host_group.cfg
	#fi
	# print_info "展示 host_group.cfg"
	# cat /usr/local/nagios/etc/objects/myservers/host_group.cfg
	# print_complete "Step 4: Nagios 服务器组配置文件： /usr/local/nagios/etc/objects/myservers/host_group.cfg"
}
#-----------------------------------------------------------------------------#
# 定制 Nagios Server Service Group
function customize_nagios_server_myservers_service_group {
	print_info "Step 6: Nagios 自定义服务组 /usr/local/nagios/etc/objects/myservers/service_group.cfg"

	# 读取文件名到数组
	local search_dir="/usr/local/nagios/etc/objects/myservers"
	local array_host
	for host_group_member in $search_dir/*
	do
		if [ -f $host_group_member ]; then
			array_host=(${array_host[*]} $host_group_member)
		fi
	done

	cat <<EOF > /usr/local/nagios/etc/objects/myservers/service_group.cfg
# 2021 July 21st
EOF

	local Service_Type
	local Service_Group_Member=$currentHost
	local tmpService_Group_Member
	local Service_Type_Index=0
	local i=0
	# local array_service=(v2ray xray trojan.go nginx httpd v2-ui x-ui webmin docker)
	# local array_service=("Service v2ray" "Service xray" "Service trojan.go" "Service nginx" "Service httpd" "Service v2-ui" "Service x-ui" "Service webmin" "Service docker" "CPU statistics" "Memory usage" Ping "Service nrpe" "Service node_exporter")
	# local array_service=("CPU statistics" "Current users" "Disk usage" "Memory usage" "Total procedures" "SSH" "Ping" "Service v2ray" "Service xray" "Service trojan.go" "Service nginx" "Service httpd" "Service v2-ui" "Service x-ui" "Service webmin" "Service docker" "Service nrpe" "Service node_exporter")
	
	# echo ${array_service[@]}
	# for i in ${array_service[*]} 
	# 数组元素有空格，要用双引号
	for i in "${array_service_description[@]}"
	do
		Service_Type=${array_service_description[Service_Type_Index]}
		# Service_Group_Member=$Service_Group_Member",Service "${Service_Type}
		Service_Group_Member=$Service_Group_Member","${Service_Type}
		local e=0
		local Myservers_Host_Index=0
		for e in ${array_host[*]}
		do
		tmpService_Group_Member=${array_host[Myservers_Host_Index]##*/}
		if [[ "${tmpService_Group_Member}" == "host_group.cfg" ]] || [[ "${tmpService_Group_Member}" == "service_group.cfg" ]] || [[ "${tmpService_Group_Member}" == "mycommands.cfg" ]] || [[ "${tmpService_Group_Member}" == "services.cfg" ]] || [[ "${tmpService_Group_Member}" == "$currentHost"".cfg" ]] ; then
			# print_error "skip file"
			# echoContent white "${tmpService_Group_Member}"
			let Myservers_Host_Index++
		else
			# Service_Group_Member=$Service_Group_Member","${tmpService_Group_Member%.*}",Service "${Service_Type}
			Service_Group_Member=$Service_Group_Member","${tmpService_Group_Member%.*}","${Service_Type}
			# print_info "$Service_Group_Member"
			let Myservers_Host_Index++
		fi
		done
		cat <<EOF >> /usr/local/nagios/etc/objects/myservers/service_group.cfg
define servicegroup{
	servicegroup_name	${Service_Type#*Service }
	alias			${Service_Type#*Service }
	members			${Service_Group_Member}
	}
EOF
		Service_Group_Member=$currentHost
		let Service_Type_Index++
	done
	chown nagios:nagios /usr/local/nagios/etc/objects/myservers/service_group.cfg
	chmod 777 /usr/local/nagios/etc/objects/myservers/service_group.cfg

}
#-----------------------------------------------------------------------------#
# 定制 Nagios Server Command
function customize_nagios_server_myservers_command {
	print_info "Step 7: Nagios 自定义命令集 /usr/local/nagios/etc/objects/myservers/mycommands.cfg"
	cat <<EOF > /usr/local/nagios/etc/objects/myservers/mycommands.cfg
################################################################################
# 2021 July 19th defined COMMANDS
################################################################################

define command {
    command_name    check_nrpe
    command_line    \$USER1\$/check_nrpe -H \$HOSTADDRESS$ -t 30 -c \$ARG1\$ \$ARG2\$
}

define command {
    command_name    check_ncpa
    command_line    \$USER1\$/check_ncpa.py -H \$HOSTADDRESS$ \$ARG1\$
}

define command {
    command_name    check_load
    command_line    \$USER1\$/check_load -w \$ARG1\$ -c \$ARG2\$
}

define command {
    command_name    check_certificate_expires
    command_line    \$USER1\$/check_tcp -H \$HOSTADDRESS$ -p 443 -w 0.5 -c 1 -t 5 -S -D 30
}

define command {
    command_name    check_ssl_certificate
    command_line    \$USER1\$/check_ssl_certificate -H \$HOSTADDRESS$ -c 10 -w 20
}

define command {
    command_name    check_port_80
    command_line    \$USER1\$/check_tcp -H \$HOSTADDRESS$ -p 80 -w 0.2 -c 0.5 -t 5
}

define command {
    command_name    check_port_443
    command_line    \$USER1\$/check_tcp -H \$HOSTADDRESS$ -p 443 -w 0.5 -c 1 -t 5 -S
}

define command {
    command_name    check_port_5666
    command_line    \$USER1\$/check_tcp -H \$HOSTADDRESS$ -p 5666 -w 0.2 -c 0.5 -t 5
}

define command {
    command_name    check_port_5693
    command_line    \$USER1\$/check_tcp -H \$HOSTADDRESS$ -p 5693 -w 0.2 -c 0.5 -t 5
}

define command {
    command_name    check_port_7080
    command_line    \$USER1\$/check_tcp -H \$HOSTADDRESS$ -p 7080 -w 0.2 -c 0.5 -t 5
}

define command {
    command_name    check_port_7443
    command_line    \$USER1\$/check_tcp -H \$HOSTADDRESS$ -p 7080 -w 0.2 -c 0.5 -t 5
}

define command {
    command_name    check_port_8080
    command_line    \$USER1\$/check_tcp -H \$HOSTADDRESS$ -p 8080 -w 0.2 -c 0.5 -t 5
}

define command {
    command_name    check_port_8443
    command_line    \$USER1\$/check_tcp -H \$HOSTADDRESS$ -p 8443 -w 0.2 -c 0.5 -t 5
}

define command {
    command_name    check_port_9100
    command_line    \$USER1\$/check_tcp -H \$HOSTADDRESS$ -p 9100 -w 0.2 -c 0.5 -t 5
}

define command {
    command_name    check_port_9999
    command_line    \$USER1\$/check_tcp -H \$HOSTADDRESS$ -p 9999 -w 0.2 -c 0.5 -t 5
}

define command {
    command_name    check_ncpa_cpu
    command_line    \$USER1\$/check_ncpa.py -H \$HOSTADDRESS$ \$ARG1\$ -t 'mytoken' -P 5693 -M cpu/percent --warning 90 --critical 95
}

define command {
    command_name    check_ncpa_memory
    command_line    \$USER1\$/check_ncpa.py -H \$HOSTADDRESS$ \$ARG1\$ -t 'mytoken' -P 5693 -M memory/virtual -w 80 -c 90 -u G
}

define command {
    command_name    check_ncpa_processes
    command_line    \$USER1\$/check_ncpa.py -H \$HOSTADDRESS$ \$ARG1\$ -t 'mytoken' -P 5693 -M processes -w 160 -c 200
}

#define command {
#    command_name    check_ncpa_processes
#    command_line    check_ncpa!-t 'mytoken' -P 5693 -M processes -w 150 -c 200
#}

define command {
    command_name    check_ncpa_service_nginx
    command_line    \$USER1\$/check_ncpa.py -H \$HOSTADDRESS$ \$ARG1\$ -t 'mytoken' -P 5693 -M services -q service=nginx,status=running
}

define command {
    command_name    check_ncpa_service_node_exporter
    command_line    \$USER1\$/check_ncpa.py -H \$HOSTADDRESS$ \$ARG1\$ -t 'mytoken' -P 5693 -M services -q service=node_exporter,status=running
}

define command {
    command_name    check_ncpa_service_nrpe
    command_line    \$USER1\$/check_ncpa.py -H \$HOSTADDRESS$ \$ARG1\$ -t 'mytoken' -P 5693 -M services -q service=nrpe,status=running
}

define command {
    command_name    check_ncpa_service_webmin
    command_line    \$USER1\$/check_ncpa.py -H \$HOSTADDRESS$ \$ARG1\$ -t 'mytoken' -P 5693 -M services -q service=webmin,status=running
}

define command {
    command_name    check_ncpa_service_xray
    command_line    \$USER1\$/check_ncpa.py -H \$HOSTADDRESS$ \$ARG1\$ -t 'mytoken' -P 5693 -M services -q service=xray,status=running
}

define command {
    command_name    check_ncpa_service_docker
    command_line    \$USER1\$/check_ncpa.py -H \$HOSTADDRESS$ \$ARG1\$ -t 'mytoken' -P 5693 -M services -q service=docker,status=running
}

define command {
    command_name    check_ncpa_service_nagios
    command_line    \$USER1\$/check_ncpa.py -H \$HOSTADDRESS$ \$ARG1\$ -t 'mytoken' -P 5693 -M services -q service=nagios,status=running
}

define command {
    command_name    check_ncpa_service_httpd
    command_line    \$USER1\$/check_ncpa.py -H \$HOSTADDRESS$ \$ARG1\$ -t 'mytoken' -P 5693 -M services -q service=httpd,status=running
}

define command {
    command_name    check_ncpa_service_x-ui
    command_line    \$USER1\$/check_ncpa.py -H \$HOSTADDRESS$ \$ARG1\$ -t 'mytoken' -P 5693 -M services -q service=x-ui,status=running
}

define command {
    command_name    check_ncpa_service_ncpa_listener
    command_line    \$USER1\$/check_ncpa.py -H \$HOSTADDRESS$ \$ARG1\$ -t 'mytoken' -P 5693 -M services -q service=ncpa_listener,status=running
}

define command {
    command_name    check_ncpa_interface_sent
    command_line    \$USER1\$/check_ncpa.py -H \$HOSTADDRESS$ \$ARG1\$ -t 'mytoken' -P 5693 -M 'interface/eth0/bytes_sent' -d -u m -w 10 -c 100
}

define command {
    command_name    check_ncpa_interface_receive
    command_line    \$USER1\$/check_ncpa.py -H \$HOSTADDRESS$ \$ARG1\$ -t 'mytoken' -P 5693 -M 'interface/eth0/bytes_recv' -d -u m -w 10 -c 100
}

define command {
    command_name    check_ncpa_disk_free
    command_line    \$USER1\$/check_ncpa.py -H \$HOSTADDRESS$ \$ARG1\$ -t 'mytoken' -P 5693 -M 'disk/logical/|/free' --warning 10: --critical 5: -u G
}

define command {
    command_name    check_ncpa_disk_used
    command_line    \$USER1\$/check_ncpa.py -H \$HOSTADDRESS$ \$ARG1\$ -t 'mytoken' -P 5693 -M 'disk/logical/|/used' --warning 10: --critical 5: -u G
}

define command {
    command_name    check_ncpa_disk
    command_line    \$USER1\$/check_ncpa.py -H \$HOSTADDRESS$ \$ARG1\$ -t 'mytoken' -P 5693 -M 'disk/logical/|' --warning 10: --critical 5: -u G
}

EOF
	chown nagios:nagios /usr/local/nagios/etc/objects/myservers/mycommands.cfg
	chmod 777 /usr/local/nagios/etc/objects/myservers/mycommands.cfg
}
#-----------------------------------------------------------------------------#
# 定制 /etc/hosts
function customize_nagios_server_hosts_ip {
	print_info "Step 8: 编辑 /etc/hosts "
	if cat /etc/hosts | grep ${NagiosClientDomain1} >/dev/null; then
   		print_error "主机地址已经添加到/etc/hosts，无需重复操作！"
	else
		print_info "Step 8-1: 写入主机IP和域名到/etc/hosts "
		cat <<EOF >> /etc/hosts
${NagiosClientIP1} ${NagiosClientDomain1}
EOF
	fi
}
#-----------------------------------------------------------------------------#
# 定制 Nagios Server Myservers Show
function customize_nagios_server_myservers_show {
	print_info "Step 9: 服务器列表"
	print_info "#------------------------------# "

	local search_dir="/usr/local/nagios/etc/objects/myservers"
	for xxmember in $search_dir/*
	do
		if [ -f $xxmember ]; then
			myservers_member_arr=(${myservers_member_arr[*]} $xxmember)
		fi
	done

	local myservers_member_index=0
	local myservers_member_count=0
	local myserver_number=0

	for myservers_member_count in ${myservers_member_arr[*]}
	do
	# 正则表达式 ${var##*/}  --> 左边算起的最后一个/字符左边的内容
	tmpMyservers_Member=${myservers_member_arr[myservers_member_index]##*/}
		if [[ "${tmpMyservers_Member}" == "host_group.cfg" ]] || [[ "${tmpMyservers_Member}" == "service_group.cfg" ]] || [[ "${tmpMyservers_Member}" == "mycommands.cfg" ]] || [[ "${tmpMyservers_Member}" == "services.cfg" ]] ; then
			let myservers_member_index++
		else
			Myservers_Member=${tmpMyservers_Member%.*}
			print_info "# 服务器域名: \c"
			echoContent white "$Myservers_Member"
			let myservers_member_index++
			let myserver_number++
		fi
	done
	print_info "# 服务器总数: \c "
	echoContent green "$myserver_number"
	print_info "#------------------------------# "
}
#-----------------------------------------------------------------------------#
# 定制 Nagios Server 重启
function customize_nagios_server_restart {
	print_info "Step 10: 重启 Nagios 服务"
	systemctl restart nagios
	# systemctl status nagios
}
#-----------------------------------------------------------------------------#
# 定制 Nagios Server
function customize_nagios_server {
	print_start "定制 Nagios Server "

	customize_nagios_server_check_myservers_folder
	customize_nagios_server_nagios_cfg
	# customize_nagios_server_myservers_three
	customize_nagios_server_myservers_host
	customize_nagios_server_myservers_services
	customize_nagios_server_myservers_host_group
	customize_nagios_server_myservers_service_group
	customize_nagios_server_myservers_command
	customize_nagios_server_hosts_ip
	customize_nagios_server_myservers_show
	customize_nagios_server_restart

	print_complete "定制 Nagios Server "
}

#-----------------------------------------------------------------------------#
# 定制 Nagios Client NRPE.cfg
function customize_nagios_client_nrpe_cfg {
	print_info "Step 1: Nagios 客户端配置文件： /usr/local/nagios/etc/nrpe.cfg "
	if [[ ! -f "/usr/local/nagios/etc/nrpe.cfg" ]]; then
		print_error "Nagios 客户端配置文件不存在，请确认是否正确安装Nagios NRPE！"
		exit 0
	else
		if [[ ! -f "/usr/local/nagios/etc/nrpe.cfg.bakcup" ]]; then
		cp -pf /usr/local/nagios/etc/nrpe.cfg /usr/local/nagios/etc/nrpe.cfg.backup
		else
			print_info "已备份 nrpe.cfg"
		fi

		# if cat /usr/local/nagios/etc/nrpe.cfg | grep "定制命令 - 2021 July 18th" >/dev/null; then
   		#	print_error "已定制过，无需重复操作！"
		# else
			print_info "Step 1-1: 添加Nagios 服务端IP # ALLOWED HOST ADDRESSES "
			# 注释掉内容
			local TMPnagiosHostIP
			read -r -p "请输入Nagios Server IP (留空使用默认地址): " TMPnagiosHostIP
			if [ $TMPnagiosHostIP ]; then
				print_info "Nagios Server IP : ${TMPnagiosHostIP}"
			else
				print_error "未检测到输入，将使用默认Nagios Server: \c "
				echoContent white "k8s-master.cf"
				TMPnagiosHostIP=$(ping k8s-master.cf -c 1 | sed '1{s/[^(]*(//;s/).*//;q}')

				# TMPnagiosHostIP=${nagiosHostIP}
				print_info "使用默认 Nagios Server IP: \c "
				echoContent white "${TMPnagiosHostIP}"
			fi
			# 双引号可以用shell变量
			# sed -i "s/allowed_hosts=127.0.0.1,::1/allowed_hosts=127.0.0.1,::1,$TMPnagiosHostIP/g" /usr/local/nagios/etc/nrpe.cfg
			print_info "Step 1-2: 添加Command "
			cat <<EOF > /usr/local/nagios/etc/nrpe.cfg
log_facility=daemon
log_file=/usr/local/nagios/var/nrpe.log
# Values: 0=debugging off, 1=debugging on
debug=0
pid_file=/usr/local/nagios/var/nrpe.pid
server_port=5666
nrpe_user=nagios
nrpe_group=nagios
allowed_hosts=127.0.0.1,::1,$TMPnagiosHostIP
dont_blame_nrpe=0
# Values: 0=do not allow bash command substitutions,
#         1=allow bash command substitutions
allow_bash_command_substitution=0
command_timeout=60
connection_timeout=300
disable_syslog=0

# 定制命令 - 2021 July 18th
command[check_users]=/usr/local/nagios/libexec/check_users -w 5 -c 10
command[check_load]=/usr/local/nagios/libexec/check_load -r -w .15,.10,.05 -c .30,.25,.20
command[check_hda1]=/usr/local/nagios/libexec/check_disk -w 20% -c 10% -p /dev/hda1
command[check_zombie_procs]=/usr/local/nagios/libexec/check_procs -w 5 -c 10 -s Z
command[check_total_procs]=/usr/local/nagios/libexec/check_procs -w 160 -c 200

command[check_mem]=/usr/local/nagios/libexec/check_mem -w 90 -c 95 -W 50 -C 80
command[check_swap]=/usr/local/nagios/libexec/check_swap -c 0

command[check_disk]=/usr/local/nagios/libexec/check_disk -w 30% -c 20% -p /
command[check_kernel]=/usr/local/nagios/libexec/check_kernel --warn-only

command[check_netint]=/usr/local/nagios/libexec/check_netinterfaces -n eth0 -f -k -z
command[check_cpu_stats]=/usr/local/nagios/libexec/check_cpu_stats.sh

command[check_v2ray]=/usr/local/nagios/libexec/check_service.sh -s v2ray
command[check_xray]=/usr/local/nagios/libexec/check_service.sh -s xray
command[check_trojan.go]=/usr/local/nagios/libexec/check_service.sh -s trojan-go
command[check_nginx]=/usr/local/nagios/libexec/check_service.sh -s nginx
command[check_httpd]=/usr/local/nagios/libexec/check_service.sh -s httpd

command[check_v2_ui]=/usr/local/nagios/libexec/check_service.sh -s v2-ui
command[check_x_ui]=/usr/local/nagios/libexec/check_service.sh -s x-ui
command[check_webmin]=/usr/local/nagios/libexec/check_service.sh -s webmin
command[check_docker]=/usr/local/nagios/libexec/check_service.sh -s docker
command[check_docker2]=/usr/local/nagios/libexec/check_docker -w 50 -c 80
command[check_nrpe]=/usr/local/nagios/libexec/check_service.sh -s nrpe
command[check_ncpa]=/usr/local/nagios/libexec/check_service.sh -s ncpa_listener
command[check_node_exporter]=/usr/local/nagios/libexec/check_service.sh -s node_exporter

#command[check_eth]=/usr/local/nagios/libexec/check_eth -i eth0 -w 2M Bps -c 10M Bps
command[check_eth]=/usr/local/nagios/libexec/check_eth -i eth0 -w 1024K Bps -c 2048K Bps

EOF
		# fi
	chown nagios:nagios /usr/local/nagios/etc/nrpe.cfg
	chmod 644 /usr/local/nagios/etc/nrpe.cfg
	fi
}
#-----------------------------------------------------------------------------#
# 定制 Nagios Client Copy Libexec
function customize_nagios_client_copy_libexec {

	# check_ssl_certificate
	yum -y install nagios-plugins-perl >/dev/null 2>&1
	# yum -y install libcrypt-ssleay-perl
	# yum -y install libcrypt-x509-perl

	print_info "Step 2: 拷贝libexec 到本地"
	if [[ -d "${GITHUB_REPO_TOOLBOX}/Nagios/Libexec" ]] ; then
		cp -pf 	${GITHUB_REPO_TOOLBOX}/Nagios/Libexec/* /usr/local/nagios/libexec/
		cp -pf 	${GITHUB_REPO_TOOLBOX}/Nagios/Libexec/*.* /usr/local/nagios/libexec/
		chmod 755 /usr/local/nagios/libexec/*
		chmod 755 /usr/local/nagios/libexec/*.*
	else
		print_error "请先Git同步toolbox到本地，再进行设置！"
		print_error "Plan B: wget 文件到Libexec"
		
#		rm -f /usr/local/nagios/libexec/check_cpu_stats.sh
#		rm -f /usr/local/nagios/libexec/check_kernel
#		rm -f /usr/local/nagios/libexec/check_mem.pl
#		rm -f /usr/local/nagios/libexec/check_mem
#		rm -f /usr/local/nagios/libexec/check_service.sh
#		rm -f /usr/local/nagios/libexec/check_ssl_certificate
#		rm -f /usr/local/nagios/libexec/check_netinterfaces
#		rm -f /usr/local/nagios/libexec/check_eth

		wget -c -q -P /tmp/ -N --no-check-certificate "https://raw.githubusercontent.com/linfengzhong/toolbox/main/Nagios/Libexec.zip"	
		unzip -o /tmp/Libexec.zip -d /tmp/ >/dev/null
		mv -f /tmp/Libexec/* /usr/local/nagios/libexec/
		
		rm -f /tmp/Libexec.zip
		rm -rf /tmp/Libexec/ 
#		wget -c -q -P /usr/local/nagios/libexec/ -N --no-check-certificate "https://raw.githubusercontent.com/linfengzhong/toolbox/main/Nagios/Libexec/check_cpu_stats.sh"
#		wget -c -q -P /usr/local/nagios/libexec/ -N --no-check-certificate "https://raw.githubusercontent.com/linfengzhong/toolbox/main/Nagios/Libexec/check_kernel"
#		wget -c -q -P /usr/local/nagios/libexec/ -N --no-check-certificate "https://raw.githubusercontent.com/linfengzhong/toolbox/main/Nagios/Libexec/check_mem.pl"
#		wget -c -q -P /usr/local/nagios/libexec/ -N --no-check-certificate "https://raw.githubusercontent.com/linfengzhong/toolbox/main/Nagios/Libexec/check_mem"
#		wget -c -q -P /usr/local/nagios/libexec/ -N --no-check-certificate "https://raw.githubusercontent.com/linfengzhong/toolbox/main/Nagios/Libexec/check_service.sh"
#		wget -c -q -P /usr/local/nagios/libexec/ -N --no-check-certificate "https://raw.githubusercontent.com/linfengzhong/toolbox/main/Nagios/Libexec/check_ssl_certificate"
#		wget -c -q -P /usr/local/nagios/libexec/ -N --no-check-certificate "https://raw.githubusercontent.com/linfengzhong/toolbox/main/Nagios/Libexec/check_ssl_cert_expiry"
#		wget -c -q -P /usr/local/nagios/libexec/ -N --no-check-certificate "https://raw.githubusercontent.com/linfengzhong/toolbox/main/Nagios/Libexec/check_netinterfaces"
#		wget -c -q -P /usr/local/nagios/libexec/ -N --no-check-certificate "https://raw.githubusercontent.com/linfengzhong/toolbox/main/Nagios/Libexec/check_eth"

		chmod 755 /usr/local/nagios/libexec/*
		chmod 755 /usr/local/nagios/libexec/*.*
	fi
}
#-----------------------------------------------------------------------------#
# 定制 Nagios Client Restart
function customize_nagios_client_restart {
	print_info "重启NRPE服务"
	systemctl restart nrpe
	# systemctl status nrpe
}
#-----------------------------------------------------------------------------#
# 定制 Nagios Client
function customize_nagios_client {
	print_start "定制 Nagios Client "

	customize_nagios_client_nrpe_cfg
	customize_nagios_client_copy_libexec
	customize_nagios_client_restart

	print_complete "定制 Nagios Client "
}
#-----------------------------------------------------------------------------#
# 激活 Nagios 黑暗模式 
function enable_nagios_dark_mode {
	print_start "激活 Nagios 黑暗模式 "
	print_info "Step 1: 备份源文件 "
	if [[ ! -d "/etc/fuckGFW/nagios/stylesheets" ]] ; then
		cp -rpf /usr/local/nagios/share/stylesheets /etc/fuckGFW/nagios/
		cp -pf /usr/local/nagios/share/index.php /etc/fuckGFW/nagios/index.php
	else
		print_error "备份已存在，无需重复备份！！！ "
	fi
	print_info "Step 2: 复制黑暗模式 "
	rm -rf /usr/local/nagios/share/stylesheets
	rm -f /usr/local/nagios/share/index.php

	if [[ -d "/root/git/toolbox/Nagios/nagios4-dark-theme-master/stylesheets" ]] ; then
		cp -rpf /root/git/toolbox/Nagios/nagios4-dark-theme-master/stylesheets /usr/local/nagios/share/
		cp -pf /root/git/toolbox/Nagios/nagios4-dark-theme-master/index.php /usr/local/nagios/share/index.php
	else
		print_error "Git未安装或未同步，执行Plan B"
		mkdir -p /usr/local/nagios/share/stylesheets
		wget -c -q -P /usr/local/nagios/share/ -N --no-check-certificate "https://raw.githubusercontent.com/linfengzhong/toolbox/main/Nagios/nagios4-dark-theme-master/stylesheets.zip"
		wget -c -q -P /usr/local/nagios/share/ -N --no-check-certificate "https://raw.githubusercontent.com/linfengzhong/toolbox/main/Nagios/nagios4-dark-theme-master/index.php"
		unzip -o /usr/local/nagios/share/stylesheets.zip -d /usr/local/nagios/share/ >/dev/null
		rm -f /usr/local/nagios/share/stylesheets.zip
	fi
	chown nagios:nagios /usr/local/nagios/share/index.php
	chown -R nagios:nagios /usr/local/nagios/share/stylesheets

	print_info "Step 3: 重启 Nagios "
	systemctl restart nagios
	# systemctl status nagios
	print_complete "激活 Nagios 黑暗模式 "
}
#-----------------------------------------------------------------------------#
# 恢复 Nagios 普通模式 
function enable_nagios_normal_mode {
	print_start "恢复 Nagios 普通模式 "
	print_info "Step 1: 复制普通模式 "
	rm -rf /usr/local/nagios/share/stylesheets
	rm -f /usr/local/nagios/share/index.php
	cp -rpf /etc/fuckGFW/nagios/stylesheets /usr/local/nagios/share/
	cp -pf /etc/fuckGFW/nagios/index.php /usr/local/nagios/share/index.php
	print_info "Step 2: 重启 Nagios "
	systemctl restart nagios
	# systemctl status nagios
	print_complete "恢复 Nagios 普通模式 "
}
#-----------------------------------------------------------------------------#
# 激活 apache httpd SSL
function enable_apache_httpd_ssl {
	print_start "激活 apache httpd SSL - Port: 8443"
	if [[ -f "/etc/httpd/conf.d/ssl.conf" ]]; then
		print_error "apache httpd SSL已经设置，无需重复操作！"
	else
		print_info "Step 1: 安装ssl认证模块 "
		yum -y install mod_ssl >/dev/null 2>&1
		print_info "Step 2: 编辑 /etc/httpd/conf.d/ssl.conf"
		cat <<EOF >/etc/httpd/conf.d/ssl.conf
Listen 8443 https

SSLPassPhraseDialog exec:/usr/libexec/httpd-ssl-pass-dialog
SSLSessionCache         shmcb:/run/httpd/sslcache(512000)
SSLSessionCacheTimeout  300
SSLCryptoDevice builtin

<VirtualHost _default_:8443>

ErrorLog logs/ssl_error_log
TransferLog logs/ssl_access_log
LogLevel warn

SSLEngine on

#SSLProtocol all -SSLv3
#SSLProxyProtocol all -SSLv3

SSLHonorCipherOrder on

SSLCipherSuite PROFILE=SYSTEM
SSLProxyCipherSuite PROFILE=SYSTEM

SSLCertificateFile /etc/fuckGFW/tls/${currentHost}.cer
SSLCertificateKeyFile /etc/fuckGFW/tls/${currentHost}.key
SSLCertificateChainFile /etc/fuckGFW/tls/fullchain.cer
SSLCACertificateFile /etc/fuckGFW/tls/ca.cer

<FilesMatch "\.(cgi|shtml|phtml|php)$">
    SSLOptions +StdEnvVars
</FilesMatch>
<Directory "/var/www/cgi-bin">
    SSLOptions +StdEnvVars
</Directory>

BrowserMatch "MSIE [2-5]" \
         nokeepalive ssl-unclean-shutdown \
         downgrade-1.0 force-response-1.0

CustomLog logs/ssl_request_log \
          "%t %h %{SSL_PROTOCOL}x %{SSL_CIPHER}x \"%r\" %b"

</VirtualHost>
EOF
		print_info "Step 3: 编辑 /etc/httpd/conf/httpd.conf "
		if cat /etc/httpd/conf/httpd.conf | grep "# 2021 July 21st" ; then
			print_error "已经设置跳转https，无需重复！"
		else
			cat <<EOF >>/etc/httpd/conf/httpd.conf
# 2021 July 21st
RewriteEngine On
RewriteCond %{HTTPS} off
RewriteRule (.*) https://%{HTTP_HOST}%{REQUEST_URI}
EOF
		fi
		print_info "Step 4: 重新启动 httpd.service "
		#重启http服务
		systemctl restart httpd.service
		#查看状态
		# systemctl status httpd.service
		print_info "Nagio 访问地址 https://${currentHost}:8443/nagios"
		print_info "Nagio 用户名：nagiosadmin"
		print_info "Nagio 密码：xxxxxx"
	fi
	print_complete "激活 apache httpd SSL - Port: 8443 "
}
#-----------------------------------------------------------------------------#
# 安装 nagios server
function install_nagios_server {
	print_start "安装 Nagios Core"
	nagios_status_running=$(systemctl status nagios | grep Active | awk '{print $3}' | cut -d "(" -f2 | cut -d ")" -f1)
	if [ "$nagios_status_running" == "running" ]  
        then  
            print_info "Nagios 服务正在运行！" 
			print_error "无需重新安装！"
		else
	# Security-Enhanced Linux
	# This guide is based on SELinux being disabled or in permissive mode. 
	# Steps to do this are as follows.
	print_info "Step 1: Security-Enhanced Linux"
	sed -i 's/SELINUX=.*/SELINUX=disabled/g' /etc/selinux/config
	setenforce 0
	# print_complete "Step 1: Security-Enhanced Linux"

	# Prerequisites
	# Perform these steps to install the pre-requisite packages.
	# httpd -> Apache Web Server
	print_info "Step 2: Prerequisites"
	yum install -y gcc glibc glibc-common perl httpd php wget gd gd-devel
	yum update -y
	print_complete "Step 2: Prerequisites"

	# Downloading the Source
	print_info "Step 3: Downloading the Source"
	print_info "nagios-4.4.6."
	cd /tmp
	wget -O nagioscore.tar.gz https://github.com/NagiosEnterprises/nagioscore/releases/download/nagios-4.4.6/nagios-4.4.6.tar.gz
	tar xzf nagioscore.tar.gz
	print_complete "Step 3: Downloading the Source"
	
	# Compile
	print_info "Step 4: Compile"
	cd /tmp/nagios-4.4.6/
	./configure
	make all
	print_complete "Step 4: Compile"

	# Create User And Group
	# This creates the nagios user and group. 
	# The apache user is also added to the nagios group.
	print_info "Step 5: Create User And Group"
	make install-groups-users
	usermod -a -G nagios apache
	print_complete "Step 5: Create User And Group"

	# Install Binaries
	# This step installs the binary files, CGIs, and HTML files.
	print_info "Step 6: Install Binaries"
	make install
	print_complete "Step 6: Install Binaries"

	# Install Service / Daemon
	# This installs the service or daemon files and also configures them to start on boot. 
	# The Apache httpd service is also configured at this point.
	print_info "Step 7: Install Service / Daemon"
	make install-daemoninit
	systemctl enable httpd.service
	print_complete "Step 7: Install Service / Daemon"

	# Install Command Mode
	# This installs and configures the external command file.
	print_info "Step 8: Install Command Mode"
	make install-commandmode
	print_complete "Step 8: Install Command Mode"

	# Install Configuration Files
	# This installs the *SAMPLE* configuration files. 
	# These are required as Nagios needs some configuration files to allow it to start.
	print_info "Step 9: Install Configuration Files"
	make install-config
	print_complete "Step 9: Install Configuration Files"

	# Install Apache Config Files
	# This installs the Apache web server configuration files. 
	# Also configure Apache settings if required.
	print_info "Step 10: Install Apache Config Files"
	make install-webconf
	print_complete "Step 10: Install Apache Config Files"

	# Configure Firewall
	# You need to allow port 80 inbound traffic on the local firewall 
	# so you can reach the Nagios Core web interface.
	print_info "Step 11: Configure Firewall"
	firewall-cmd --zone=public --add-port=8080/tcp
	firewall-cmd --zone=public --add-port=8080/tcp --permanent
	print_complete "Step 11: Configure Firewall"

	# Create nagiosadmin User Account
	# You'll need to create an Apache user account to be able to log into Nagios.
	# The following command will create a user account called nagiosadmin and 
	# you will be prompted to provide a password for the account.
	print_info "Step 12: Create nagiosadmin User Account"
	htpasswd -c /usr/local/nagios/etc/htpasswd.users nagiosadmin
	print_complete "Step 12: Create nagiosadmin User Account"

	# Start Apache Web Server
	print_info "Step 13: Start Apache Web Server"
	systemctl start httpd.service
	print_complete "Step 13: Start Apache Web Server"

	# Start Service / Daemon
	# This command starts Nagios Core.
	print_info "Step 14: Start Service / Daemon for Nagios Core"
	systemctl start nagios.service
	print_complete "Step 14: Start Service / Daemon for Nagios Core"

	# Test Nagios
	# Nagios is now running, to confirm this you need to log into the Nagios Web Interface.
	# Point your web browser to the ip address or FQDN of your Nagios Core server, 
	# for example:
	# http://10.25.5.143/nagios
	# http://core-013.domain.local/nagios
	fi
	print_complete "安装 Nagios Core"
}
#-----------------------------------------------------------------------------#
# 安装 nagios plugins
function install_nagios_plugins {
	print_start "安装 Nagios Plugins 2.3.3"
	if [[ -f "/usr/local/nagios/libexec/check_cpu_stats.sh" ]]; then
        print_info "Nagios Plugins 服务正在运行！" 
		print_error "无需重复安装！"
	else
	# 2021-April-06 [Initial Version] - Shell Script for Nagios Plugins installing
	# Nagios Plugins - Installing Nagios Plugins From Source

	# Security-Enhanced Linux
	# This guide is based on SELinux being disabled or in permissive mode. 
	# Steps to do this are as follows.
	print_info "Step 1: Security-Enhanced Linux"
	sed -i 's/SELINUX=.*/SELINUX=disabled/g' /etc/selinux/config
	setenforce 0
	# print_complete "Step 1: Security-Enhanced Linux"

	# Prerequisites
	# Perform these steps to install the pre-requisite packages.
	print_info "Step 2: Prerequisites"
	sleep 2
	yum install -y gcc glibc glibc-common make gettext automake autoconf wget openssl-devel net-snmp net-snmp-utils epel-release
	yum --enablerepo=PowerTools,epel install perl-Net-SNMP
	yum -y install sysstat
	print_complete "Step 2: Prerequisites"

	# Downloading the Source
	print_info "Step 3: 下载Nagios Plugins 2.2.3 到tmp文件夹"
	cd /tmp
	wget --no-check-certificate https://github.com/nagios-plugins/nagios-plugins/releases/download/release-2.3.3/nagios-plugins-2.3.3.tar.gz
	tar xzf nagios-plugins-2.3.3.tar.gz
	cd nagios-plugins-2.3.3
	print_complete "Step 3: 下载Nagios Plugins 2.2.3 到tmp文件夹"

	# Nagios Plugins Installation
	print_info "Step 4: 安装nagios plugins, 并重新启动nrpe服务"
	./tools/setup
	./configure
	make
	make install
	systemctl restart nrpe
	print_complete "Step 4: 安装nagios plugins, 并重新启动nrpe服务"
	fi
	print_complete "安装 Nagios Plugins 2.3.3"
}
#-----------------------------------------------------------------------------#
# 安装 nagios nrpe
function install_nagios_nrpe {
	print_start "安装 Nagios NRPE"
	# NRPE - Nagios Remote Plugin Executor
	nrpe_status_running=$(systemctl status nrpe | grep Active | awk '{print $3}' | cut -d "(" -f2 | cut -d ")" -f1)
	if [ "$nrpe_status_running" == "running" ]  
        then  
            print_info "NRPE 服务正在运行！" 
			print_error "无需重新安装！"
		else
	#*** Configuration summary for nrpe 4.0.3 2020-04-28 ***:
	#
	# General Options:
	# -------------------------
	# NRPE port:    5666
	# NRPE user:    nagios
	# NRPE group:   nagios
	# Nagios user:  nagios
	# Nagios group: nagios

	#Security-Enhanced Linux
	#This guide is based on SELinux being disabled or in permissive mode. Steps to do this are as follows.
	print_info "Step 1: SELINUX Disable"
	sed -i 's/SELINUX=.*/SELINUX=disabled/g' /etc/selinux/config
	setenforce 0
	# print_complete "Step 1: SELINUX Disable"

	#Prerequisites
	#Perform these steps to install the pre-requisite packages.
	print_info "Step 2: Prerequisites"
	yum install -y gcc glibc glibc-common make gettext automake autoconf wget openssl-devel net-snmp net-snmp-utils epel-release
	# yum --enablerepo=PowerTools,epel install perl-Net-SNMP
	print_complete "Step 2: Prerequisites"

	#Download NRPE package
	#下载NRPE包
	print_info "Step 3: 下载nrpe-4.0.3到tmp文件夹"
	cd /tmp
	wget https://github.com/NagiosEnterprises/nrpe/releases/download/nrpe-4.0.3/nrpe-4.0.3.tar.gz
	tar xzf nrpe-4.0.3.tar.gz
	cd nrpe-4.0.3
	print_complete "Step 3: 下载nrpe-4.0.3到tmp文件夹"

	#NPRE Installation
	print_info "Step 4: 安装nrpe，设置用户和用户组、并初始化和启动nrpe服务"
	./configure
	make all
	make install-groups-users
	make install
	make install-config
	make install-init
	systemctl enable nrpe 
	systemctl start nrpe
	print_complete "Step 4: 安装nrpe，设置用户和用户组、并初始化和启动nrpe服务"

	#firewall enable port 5666
	#===== RHEL 7/8 | CentOS 7/8 | Oracle Linux 7/8 =====
	print_info "Step 5: 设置防火墙开启端口 5666"
	firewall-cmd --zone=public --add-port=5666/tcp
	firewall-cmd --zone=public --add-port=5666/tcp --permanent
	print_complete "Step 5: 设置防火墙开启端口 5666"
	fi
	print_complete "安装 Nagios NRPE"
}
#-----------------------------------------------------------------------------#
# 安装 nagios ncpa
function install_nagios_ncpa {
	print_start "安装 Nagios NCPA "
	ncpa_status_running=$(systemctl status ncpa_listener.service | grep Active | awk '{print $3}' | cut -d "(" -f2 | cut -d ")" -f1)
	if [ "$ncpa_status_running" == "running" ]  
        then  
            print_info "NCPA 服务正在运行！" 
			print_error "无需重新安装！"
		else

	# Nagios Cross-Platform Agent
	print_info "Installing the Nagios Repository"
	rpm -Uvh https://repo.nagios.com/nagios/8/nagios-repo-8-1.el8.noarch.rpm

	print_info "Installing NCPA"
	yum install ncpa -y

	print_info "展示 NCPA 配置文件 /usr/local/ncpa/etc/ncpa.cfg"
	cat /usr/local/ncpa/etc/ncpa.cfg
	
	sudo ln -s /usr/bin/python3 /usr/bin/python >/dev/null 2>&1
	print_info "访问 https://${currentHost}:5693/"

	fi
	print_complete "安装 Nagios NCPA "
}
#-----------------------------------------------------------------------------#
# 卸载 nagios ncpa
function uninstall_nagios_ncpa {
	# Nagios Cross-Platform Agent
	print_start "卸载 Nagios NCPA "

	print_info "Uninstalling NCPA"
	yum -y remove ncpa

	print_complete "卸载 Nagios NCPA "
}

#-----------------------------------------------------------------------------#
# Nagios 安装菜单
function nagios_menu() {
	clear
	cd "$HOME" || exit
	echoContent red "=================================================================="
	echoContent green "Nagios.sh：\c"
	echoContent white "${NagiosVersion}"
	echoContent green "Github：\c"
	echoContent white "https://github.com/linfengzhong/smarttool"
	echoContent green "初始化服务器、安装Docker、执行容器、科学上网 on \c" 
	echoContent white "${currentHost}"
	echoContent green "当前主机外部IP地址： \c" 
	echoContent white "${currentIP}"	
	echoContent green "当前UUID： \c" 
	echoContent white "${currentUUID}"
	echoContent green "当前系统Linux版本 : \c" 
	checkSystem
	echoContent red "=================================================================="
	echoContent skyBlue "----------------------------安装菜单------------------------------"
	echoContent yellow "0.安装 全部软件 "	
	echoContent yellow "1.安装 httpd - port: 8080 & port: 8443 "
	echoContent yellow "2.安装 nagios server "
	echoContent yellow "3.安装 nagios nrpe "
	echoContent yellow "4.安装 nagios ncpa "
	echoContent yellow "5.安装 nagios plugins "
	echoContent skyBlue "----------------------------配置菜单------------------------------"
	echoContent yellow "6.定制 nagios server "
	echoContent yellow "7.定制 nagios client "
	echoContent skyBlue "----------------------------主题选择------------------------------"
	echoContent yellow "8.激活 nagios server dark mode "
	echoContent yellow "9.激活 nagios server normal mode "
	echoContent skyBlue "----------------------------选装菜单------------------------------"
	echoContent yellow "10.展示 nagios server 配置文件 "
	echoContent yellow "11.展示 nagios client 配置文件 "
	echoContent yellow "12.清除 nagios myservers 文件夹 "
	echoContent yellow "13.卸载 nagios ncpa "
	echoContent skyBlue "----------------------------测试配置------------------------------"
	echoContent yellow "00.测试 nagios server 配置文件 "
	echoContent red "=================================================================="
	read -r -p "Please choose the function (请选择) : " selectInstallType
	case ${selectInstallType} in
	0)
		install_apache_httpd
		enable_apache_httpd_ssl
		install_nagios_server
		install_nagios_nrpe
		install_nagios_ncpa
		install_nagios_plugins
		;;
	1)
		install_apache_httpd
		enable_apache_httpd_ssl
		;;
	2)
		install_nagios_server
		;;
	3)
		install_nagios_nrpe
		;;
	4)
		install_nagios_ncpa
		;;
	5)
		install_nagios_plugins
		;;
	6)
		customize_nagios_server
		;;
	7)
		customize_nagios_client
		;;
	8)
		enable_nagios_dark_mode
		;;
	9)
		enable_nagios_normal_mode
		;;
	10)
		cat /usr/local/nagios/etc/nagios.cfg
		;;
	11)
		cat /usr/local/nagios/etc/nrpe.cfg
		;;
	12)
		rm -rf /usr/local/nagios/etc/objects/myservers
		nagios_menu
		;;
	13)
		uninstall_nagios_ncpa
		;;
	00)
		/usr/local/nagios/bin/nagios -v /usr/local/nagios/etc/nagios.cfg
		;;
	*)
		print_error "请输入正确的数字"
		sleep 1
		;;
	esac
}
NagiosVersion=v0.01
cleanScreen
inital_smart_tool $1
set_current_host_domain
nagios_menu