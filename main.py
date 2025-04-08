#!/usr/bin/env python3

import npyscreen
import time
import ipaddress
import re
import os
import configparser
from datetime import datetime
from netmiko import ConnectHandler
from cve_ros_ver_mapping import ros_cve_db
from packaging.version import Version

from pdf_report_generator import PDFReportGenerator
from check_metadata import CheckMetadata

class RouterOSInspectorApp(npyscreen.NPSAppManaged):
    def onStart(self):
        self.addForm("MAIN", MainForm, name="RouterOS Security Inspector")
        self.addForm("MENU", MenuForm, name="Inspection Menu")
        self.addForm("INDIVIDUAL", IndividualChecksForm, name="Individual Checks")
        self.addForm("RESULTS", ResultsForm, name="Inspection Results")

class MainForm(npyscreen.Form):
    CONFIG_FILE = os.path.expanduser(".routeros_inspector.conf")

    def create(self):
        self.add(npyscreen.TitleText, name="RouterOS Security Inspector", editable=False)
        config = self.load_config()
        default_ip = config.get("Connection", "ip", fallback="192.168.1.1")
        default_username = config.get("Connection", "username", fallback="admin")
        default_port = config.get("Connection", "port", fallback="22")

        self.ip = self.add(npyscreen.TitleText, name="Router IP:", value=default_ip)
        self.username = self.add(npyscreen.TitleText, name="SSH Username:", value=default_username)
        self.password = self.add(npyscreen.TitlePassword, name="SSH Password:")
        self.port = self.add(npyscreen.TitleText, name="SSH Port:", value=default_port)
        
        self.add(npyscreen.ButtonPress, name="Connect", when_pressed_function=self.connect)
        self.add(npyscreen.ButtonPress, name="Exit", when_pressed_function=self.exit_app)

    def load_config(self):
        config = configparser.ConfigParser()
        if os.path.exists(self.CONFIG_FILE):
            config.read(self.CONFIG_FILE)
        return config

    def save_config(self, ip, username, port):
        config = configparser.ConfigParser()
        config["Connection"] = {"ip": ip, "username": username, "port": str(port)}
        try:
            with open(self.CONFIG_FILE, "w") as configfile:
                config.write(configfile)
        except Exception as e:
            npyscreen.notify_confirm(f"Failed to save config: {str(e)}", title="Warning")

    def validate_ip(self, ip_str):
        try:
            ipaddress.ip_address(ip_str.strip())
            return True
        except ValueError:
            return False

    def validate_username(self, username):
        return bool(username.strip() and re.match(r'^[\w-]+$', username.strip()))

    def validate_password(self, password):
        return bool(password.strip())

    def validate_port(self, port_str):
        try:
            port = int(port_str.strip())
            return 1 <= port <= 65535
        except ValueError:
            return False

    def connect(self):
        if not self.validate_ip(self.ip.value):
            npyscreen.notify_confirm("Please enter a valid IP address!", title="Error")
            return
        if not self.validate_username(self.username.value):
            npyscreen.notify_confirm("Username must contain only letters, digits, hyphens, or underscores!", title="Error")
            return
        if not self.validate_password(self.password.value):
            npyscreen.notify_confirm("Password cannot be empty!", title="Error")
            return
        if not self.validate_port(self.port.value):
            npyscreen.notify_confirm("Port must be a number between 1 and 65535!", title="Error")
            return

        # Окно дисклеймера
        if not npyscreen.notify_yes_no("WARNING: Use this tool only for your own devices.\n\nProceed?", title="Legal Confirmation"):
            self.parentApp.switchForm("MAIN")
            return

        # Сохранение конфига и заполнение параметров для последующих подключений
        try:
            port = int(self.port.value.strip())
            self.save_config(self.ip.value.strip(), self.username.value.strip(), port)
            self.parentApp.getForm("MENU").set_connection_params(self.ip.value.strip(), self.username.value.strip(), self.password.value.strip(), port)
            self.parentApp.switchForm("MENU")
        except Exception as e:
            npyscreen.notify_confirm(f"Unexpected error: {str(e)}", title="Error")

    def exit_app(self):
        self.parentApp.switchForm(None)

class MenuForm(npyscreen.Form):
    def create(self):
        self.add(npyscreen.TitleText, name="Inspection Menu", editable=False)
        self.add(npyscreen.ButtonPress, name="Full Inspection", when_pressed_function=self.full_inspection)
        self.add(npyscreen.ButtonPress, name="Individual Checks", when_pressed_function=self.individual_checks)
        self.add(npyscreen.ButtonPress, name="Back", when_pressed_function=self.back_to_main)

    def set_connection_params(self, ip, username, password, port):
        self.ip = ip
        self.username = username
        self.password = password
        self.port = port

    def full_inspection(self):
        """Полное сканирование"""
        self.parentApp.getForm("RESULTS").set_connection_params(self.ip, self.username, self.password, self.port, full=True)
        self.parentApp.switchForm("RESULTS")

    def individual_checks(self):
        """Настраиваемое сканирование"""
        self.parentApp.getForm("INDIVIDUAL").set_connection_params(self.ip, self.username, self.password, self.port)
        self.parentApp.switchForm("INDIVIDUAL")

    def back_to_main(self):
        self.parentApp.switchForm("MAIN")

class IndividualChecksForm(npyscreen.Form):
    def create(self):
        self.add(npyscreen.TitleText, name="Select Individual Checks", editable=False)
        self.checks = self.add(npyscreen.MultiSelect, name="Checks to Run:", values=[
            "RouterOS Version",
            "SMB Service",
            "RMI Services",
            "Default Users",
            "RMI Access",
            "Wi-Fi Security",
            "UPnP Status",
            "DNS Status",
            "DDNS Status",
            "PoE Status",
            "RouterBOOT Protection",
            "SOCKS Proxy",
            "Neighbor Discovery",
            "Password Policy",
            "SSH Security",
            "Connection Tracking",
            "RoMON Status",
            "MAC Winbox Security",
            "SNMP Community",
            "NAT Rules",
            "Schedulers",
            "Static DNS",
            "Router Uptime"
        ], scroll_exit=True, max_height=10)
        self.add(npyscreen.ButtonPress, name="Run Selected Checks", when_pressed_function=self.run_checks)
        self.add(npyscreen.ButtonPress, name="Back", when_pressed_function=self.back_to_menu)

    def set_connection_params(self, ip, username, password, port):
        self.ip = ip
        self.username = username
        self.password = password
        self.port = port

    def run_checks(self):
        """Запуск проверок"""
        selected = [self.checks.values[i] for i in self.checks.value]
        if not selected:
            npyscreen.notify_confirm("Please select at least one check!", title="Error")
            return
        self.parentApp.getForm("RESULTS").set_connection_params(self.ip, self.username, self.password, self.port, full=False, selected_checks=selected)
        self.parentApp.switchForm("RESULTS")

    def back_to_menu(self):
        self.parentApp.switchForm("MENU")

class ResultsForm(npyscreen.Form):
    def create(self):
        self.output = self.add(npyscreen.Pager, name="Scan Results:", max_height=20, scroll_exit=True)
        self.checks_data = []
        self.add(npyscreen.ButtonPress, name="Generate PDF Report", when_pressed_function=self.generate_pdf)
        self.add(npyscreen.ButtonPress, name="Back to Menu", when_pressed_function=self.back_to_menu)

    def set_connection_params(self, ip, username, password, port, full=True, selected_checks=None):
        # Параметры подключения
        self.ip = ip
        self.username = username
        self.password = password
        self.port = port

        # Режимы работы (полная/выборочная проверка)
        self.full = full
        self.selected_checks = selected_checks or []

        self.checks_data = [CheckMetadata(f"Scan started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")]
        self.update_output()
        self.run_inspection()

    def append_output(self, check_metadata):
        """Добавление результатов в Pager (вывод консоли)"""
        self.checks_data.append(check_metadata)
        self.update_output()

    def update_output(self):
        self.output.values = [check.result for check in self.checks_data]
        self.output.display()

    def back_to_menu(self):
        self.parentApp.switchForm("MENU")

    def generate_pdf(self):
        """Генерация PDF-отчета"""
        default_path = os.path.join(os.getcwd(), f"RouterOS_Scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
        try:
            generator = PDFReportGenerator(self.checks_data, default_path)
            generator.build()
            npyscreen.notify_confirm(f"PDF report saved to:\n{default_path}", title="Success")
        except Exception as e:
            npyscreen.notify_confirm(f"Failed to generate PDF: {e}", title="Error")

    def connect_to_router(self):
        device = {
            "device_type": "mikrotik_routeros",
            "host": self.ip,
            "username": self.username,
            "password": self.password,
            "port": self.port,
        }
        try:
            self.append_output(CheckMetadata(f"[*] Connecting to RouterOS at {self.ip}:{self.port}"))
            connection = ConnectHandler(**device)
            self.append_output(CheckMetadata("[*] Connection successful!"))
            return connection
        except Exception as e:
            self.append_output(CheckMetadata(f"[-] Connection failed: {e}"))
            raise

    def separator(self, title):
        self.append_output(CheckMetadata(result="=" * 40))
        self.append_output(CheckMetadata(result=f"[*] {title}"))

    def parse_version(self, version_str):
        return Version(version_str)

    def extract_version_from_cve(self, description):
        """Извлечение версий из словаря CVE"""
        range_match = re.search(r"v?(\d+\.\d+(?:\.\d+)?)\s*to\s*v?(\d+\.\d+(?:\.\d+)?)", description, re.IGNORECASE)
        if range_match:
            start_version, end_version = range_match.groups()
            return "range", self.parse_version(start_version), self.parse_version(end_version)
        keyword_match = re.search(r"(before|through|after|and below)?\s*v?(\d+\.\d+(?:\.\d+)?)", description, re.IGNORECASE)
        if keyword_match:
            keyword, version = keyword_match.groups()
            return keyword, None, self.parse_version(version)
        wildcard_match = re.search(r"v?(\d+\.\d+)\.x", description, re.IGNORECASE)
        if wildcard_match:
            base_version = wildcard_match.group(1)
            return "before", None, self.parse_version(base_version + ".999")
        return None, None, None

    def check_routeros_version(self, connection):
        """Проверка на CVE на основе версии"""
        self.separator("Checking RouterOS Version")
        command = "/system resource print"
        output = connection.send_command(command)
        match = re.search(r"version:\s*([\d.]+)", output)
        if match:
            routeros_version = self.parse_version(match.group(1))
            self.append_output(CheckMetadata(
                result=f"[+] Detected RouterOS Version: {routeros_version}",
                description="Detected the installed RouterOS version.",
                fix=""
            ))
            found_cves = []
            for cve, description in ros_cve_db.items():
                keyword, start_version, end_version = self.extract_version_from_cve(description)
                if keyword == "range" and start_version and end_version:
                    if start_version <= routeros_version <= end_version:
                        found_cves.append((cve, description))
                elif keyword and end_version:
                    if keyword == "before" and routeros_version < end_version:
                        found_cves.append((cve, description))
                    elif keyword == "through" and routeros_version <= end_version:
                        found_cves.append((cve, description))
                    elif keyword == "after" and routeros_version > end_version:
                        found_cves.append((cve, description))
                    elif keyword == "and below" and routeros_version <= end_version:
                        found_cves.append((cve, description))
                elif str(routeros_version) in description:
                    found_cves.append((cve, description))
            if found_cves:
                self.append_output(CheckMetadata(
                    result=f"[!] CAUTION: Found {len(found_cves)} CVEs affecting RouterOS {routeros_version}!",
                    description="Known vulnerabilities found for this RouterOS version.",
                    fix="Update RouterOS to the latest stable version."
                ))
                for cve, description in found_cves:
                    self.append_output(CheckMetadata(
                        result=f"    - {cve}: {description}",
                        description="",
                        fix=""
                    ))
            else:
                self.append_output(CheckMetadata(
                    result="[+] No known CVEs found for this version.",
                    description="No known vulnerabilities detected.",
                    fix=""
                ))
        else:
            self.append_output(CheckMetadata(
                result="[-] ERROR: Could not determine RouterOS version.",
                description="Failed to retrieve version information.",
                fix="Check device connectivity or command syntax."
            ))

    def check_smb(self, connection):
        """Проверка, что SMB включен"""
        self.separator("Checking SMB Service")
        command = "/ip smb print"
        output = connection.send_command(command)
        if "enabled: yes" in output:
            self.append_output(CheckMetadata(
                result="[!] CAUTION: SMB service is enabled! Did you turn it on? Do you need SMB?",
                description="SMB service is active, potentially exposing file sharing vulnerabilities.",
                fix="Disable SMB via '/ip smb set enabled=no' unless required."
            ))
        else:
            self.append_output(CheckMetadata(
                result="[+] SMB is disabled. No risk detected.",
                description="SMB service is not active.",
                fix=""
            ))

    def check_rmi_services(self, connection):
        """Проверка сервисов удаленного управления"""
        self.separator("Checking RMI Services")
        command = "/ip service print"
        output = connection.send_command(command)

        # Протоколы с высоким риском, данные передаются в открытом виде
        high_risk = ["telnet", "ftp", "www"]
        
        # Протоколы с управляемый риском - защита передачи данных лежит на организации доступа к протоколам управления
        moderate_risk = ["api", "api-ssl", "winbox", "www-ssl"]
        
        # Оптимальный способ управления
        safe = ["ssh"]
        
        risks_found = False
        for line in output.splitlines():
            line = line.strip()
            if re.search(r"^\d+\s+X", line):
                continue
            match = re.search(r"(\S+)\s+\d+", line)
            if match:
                service_name = match.group(1).lower()
                display_name = service_name.upper().replace("WWW", "HTTP").replace("WWW-SSL", "HTTPS")
                if service_name in high_risk:
                    self.append_output(CheckMetadata(
                        result=f"[!] ALERT: {display_name} is ENABLED! This is a high security risk.",
                        description=f"{display_name} service is enabled, posing a significant security risk.",
                        fix=f"Disable {display_name} via '/ip service set {service_name} disabled=yes'"
                    ))
                    risks_found = True
                elif service_name in moderate_risk:
                    self.append_output(CheckMetadata(
                        result=f"[!] CAUTION: {display_name} is enabled.",
                        description=f"{display_name} service is enabled, consider if it's necessary.",
                        fix=f"Disable {display_name} via '/ip service set {service_name} disabled=yes' if not needed."
                    ))
                elif service_name in safe:
                    self.append_output(CheckMetadata(
                        result=f"[+] OK: {display_name} is enabled.",
                        description=f"{display_name} service is enabled and considered safe.",
                        fix=""
                    ))
        if not risks_found:
            self.append_output(CheckMetadata(
                result="[+] No high-risk RMI services enabled.",
                description="No high-risk remote management services detected.",
                fix=""
            ))

    def checking_access_to_RMI(self, connection):
        """Проверка доступа к сервисам удаленного доступа"""
        self.separator("Checking network access to RMI")
        command = "/ip service print detail"
        output = connection.send_command(command)
        risks_found = False
        for line in output.split("\n\n"):
            service_match = re.search(r'name="([^"]+)"', line)
            address_match = re.search(r'address=([\d./,]+)', line)
            if service_match:
                service_name = service_match.group(1)
                if address_match:
                    address_list = address_match.group(1).split(",")
                    if "0.0.0.0/0" in address_list:
                        self.append_output(CheckMetadata(
                            result=f"[!] CAUTION: {service_name.upper()} is exposed to the entire network!",
                            description=f"{service_name.upper()} is accessible from any IP.",
                            fix=f"Restrict access via '/ip service set {service_name} address=<trusted_IPs>'"
                        ))
                        risks_found = True
                    else:
                        self.append_output(CheckMetadata(
                            result=f"[+] OK! {service_name.upper()} is restricted to: {', '.join(address_list)}",
                            description=f"{service_name.upper()} access is limited to specific IPs.",
                            fix=""
                        ))
                else:
                    self.append_output(CheckMetadata(
                        result=f"[!] CAUTION: {service_name.upper()} has no IP restriction set!",
                        description=f"{service_name.upper()} has no access restrictions.",
                        fix=f"Set restrictions via '/ip service set {service_name} address=<trusted_IPs>'"
                    ))
                    risks_found = True
        if not risks_found:
            self.append_output(CheckMetadata(
                result="[+] All services have proper IP restrictions.",
                description="All RMI services have appropriate access restrictions.",
                fix=""
            ))

    def check_default_users(self, connection):
        """Проверка отсутствия стандартных пользователей"""
        self.separator("Checking Default Usernames")
        command = "/user print detail"
        output = connection.send_command(command)
        default_users = {"admin", "engineer", "user", "test", "root", "mikrotik", "routeros"}
        risks_found = False
        for line in output.split("\n\n"):
            match = re.search(r"name=\"?(\w+)\"?", line)
            if match and match.group(1).lower() in default_users:
                self.append_output(CheckMetadata(
                    result=f"[!] CAUTION: Default username '{match.group(1)}' detected!",
                    description="Default username detected, which is a security risk.",
                    fix=f"Remove or rename via '/user remove {match.group(1)}' or '/user set {match.group(1)} name=<new_name>'"
                ))
                risks_found = True
        if not risks_found:
            self.append_output(CheckMetadata(
                result="[+] No default usernames found.",
                description="No default usernames detected.",
                fix=""
            ))

    def check_wifi_security(self, connection):
        """Проверка безопасности конфигурации Wi-Fi"""
        self.separator("Checking Wi-Fi Security")
        risks_found = False

        try:
            # Retrieve RouterOS version to determine supported commands
            command = "/system resource print"
            output = connection.send_command(command)
            version_match = re.search(r"version:\s*([\d.]+)", output)
            routeros_version = Version(version_match.group(1)) if version_match else Version("0.0.0")

            # Wi-Fi (ROS v6/v7)
            commands = ["/interface wifi print detail", "/interface wireless print detail"]
            found_valid_output = False

            for command in commands:
                output = connection.send_command(command)
                if "bad command name" not in output.lower() and output.strip():
                    found_valid_output = True
                    interfaces = output.split("\n\n")
                    for interface in interfaces:
                        name_match = re.search(r'name="([^"]+)"', interface)
                        default_name_match = re.search(r'default-name="([^"]+)"', interface)
                        pmkid_match = re.search(r'disable-pmkid=(\S+)', interface)
                        wps_match = re.search(r'wps=(\S+)', interface)

                        name = name_match.group(1) if name_match else (default_name_match.group(1) if default_name_match else "Unknown")
                        pmkid = pmkid_match.group(1) if pmkid_match else "unknown"
                        wps = wps_match.group(1) if wps_match else None

                        if pmkid == "no":
                            self.append_output(CheckMetadata(
                                result=f"[!] ALERT: Wi-Fi '{name}' has insecure settings!",
                                description="PMKID attack is possible (disable-pmkid=no).",
                                fix=f"Enable PMKID disabling via '/interface wifi set {name} disable-pmkid=yes'"
                            ))
                            risks_found = True

                        if wps is not None and wps != "disable":
                            self.append_output(CheckMetadata(
                                result=f"[!] ALERT: Wi-Fi '{name}' has WPS enabled ({wps})!",
                                description="WPS is enabled, risking PIN bruteforcing and Pixie Dust attacks.",
                                fix=f"Disable WPS via '/interface wifi set {name} wps=disable'"
                            ))
                            risks_found = True

            if not found_valid_output:
                self.append_output(CheckMetadata(
                    result="[-] ERROR: Unable to retrieve Wi-Fi interface settings.",
                    description="Unsupported RouterOS version or missing interface.",
                    fix="Check device support for Wi-Fi commands."
                ))

            # Security profiles (ROS v6)
            security_profiles_output = connection.send_command("/interface wireless security-profiles print detail")
            if security_profiles_output.strip():
                profiles = security_profiles_output.split("\n\n")
                for profile in profiles:
                    profile_name_match = re.search(r'name="([^"]+)"', profile)
                    pmkid_match = re.search(r'disable-pmkid=(\S+)', profile)

                    profile_name = profile_name_match.group(1) if profile_name_match else "Unknown"
                    pmkid = pmkid_match.group(1) if pmkid_match else "unknown"

                    if pmkid == "no":
                        self.append_output(CheckMetadata(
                            result=f"[!] ALERT: Security Profile '{profile_name}' allows PMKID attack!",
                            description="PMKID attack is possible (disable-pmkid=no).",
                            fix=f"Enable PMKID disabling via '/interface wireless security-profiles set {profile_name} disable-pmkid=yes'"
                        ))
                        risks_found = True

            # /interface wifi security print (ROS v7.10+ only)
            if routeros_version >= Version("7.10"):
                security_output = connection.send_command("/interface wifi security print")
                if security_output.strip():
                    securities = security_output.split("\n\n")
                    for security in securities:
                        sec_name_match = re.search(r'name="([^"]+)"', security)
                        pmkid_match = re.search(r'disable-pmkid=(\S+)', security)
                        wps_match = re.search(r'wps=(\S+)', security)

                        if sec_name_match and (pmkid_match or wps_match):
                            sec_name = sec_name_match.group(1)
                            pmkid = pmkid_match.group(1) if pmkid_match else "unknown"
                            wps = wps_match.group(1) if wps_match else None

                            if pmkid == "no":
                                self.append_output(CheckMetadata(
                                    result=f"[!] ALERT: Wi-Fi security profile '{sec_name}' has insecure settings!",
                                    description="PMKID attack is possible (disable-pmkid=no).",
                                    fix=f"Enable PMKID disabling via '/interface wifi security set {sec_name} disable-pmkid=yes'"
                                ))
                                risks_found = True

                            if wps is not None and wps != "disable":
                                self.append_output(CheckMetadata(
                                    result=f"[!] ALERT: Wi-Fi security profile '{sec_name}' has WPS enabled ({wps})!",
                                    description="WPS is enabled, risking PIN bruteforcing and Pixie Dust attacks.",
                                    fix=f"Disable WPS via '/interface wifi security set {sec_name} wps=disable'"
                                ))
                                risks_found = True
                else:
                    self.append_output(CheckMetadata(
                        result="[-] ERROR: Unable to retrieve Wi-Fi security settings.",
                        description="Failed to retrieve Wi-Fi security configuration.",
                        fix="Check device support for '/interface wifi security print'."
                    ))
            else:
                self.append_output(CheckMetadata(
                    result="[*] Skipping '/interface wifi security print' (not supported in this version).",
                    description="This check requires RouterOS v7.10 or higher.",
                    fix=""
                ))

        except Exception as e:
            self.append_output(CheckMetadata(
                result=f"[-] ERROR: Failed to check Wi-Fi settings: {e}",
                description="An error occurred during Wi-Fi security check.",
                fix="Verify connectivity and command syntax."
            ))

        if not risks_found:
            self.append_output(CheckMetadata(
                result="[+] All Wi-Fi interfaces and security profiles have secure settings.",
                description="Wi-Fi settings are configured securely.",
                fix=""
            ))
            self.append_output(CheckMetadata(
                result="[*] If using WPA-PSK or WPA2-PSK, ensure strong passwords.",
                description="Weak passwords can be brute-forced in handshakes.",
                fix="Update passwords via security profile settings if needed."
            ))

    def check_upnp_status(self, connection):
        """Проверка, что UPnP выключен"""
        self.separator("Checking UPnP Status")
        command = "/ip upnp print"
        output = connection.send_command(command)
        if "enabled: yes" in output:
            self.append_output(CheckMetadata(
                result="[!] ALERT: UPnP is ENABLED! This is insecure.",
                description="UPnP is enabled, potentially allowing unauthorized port mapping.",
                fix="Disable UPnP via '/ip upnp set enabled=no'"
            ))
        else:
            self.append_output(CheckMetadata(
                result="[+] UPnP is disabled. No risk detected.",
                description="UPnP is disabled, reducing security risks.",
                fix=""
            ))

    def check_dns_status(self, connection):
        """Проверка, выступает ли роутер DNS-сервером"""
        self.separator("Checking DNS Settings")
        command = "/ip dns print"
        output = connection.send_command(command)
        if "allow-remote-requests: yes" in output:
            self.append_output(CheckMetadata(
                result="[!] CAUTION: Router is acting as a DNS server!",
                description="Router accepts remote DNS requests, which could be exploited.",
                fix="Disable via '/ip dns set allow-remote-requests=no'"
            ))
        else:
            self.append_output(CheckMetadata(
                result="[+] DNS remote requests are disabled.",
                description="Remote DNS requests are not allowed.",
                fix=""
            ))

    def check_ddns_status(self, connection):
        """Проверка параметров динамического DNS"""
        self.separator("Checking DDNS Settings")
        command = "/ip cloud print"
        output = connection.send_command(command)
        if "ddns-enabled: yes" in output:
            self.append_output(CheckMetadata(
                result="[!] CAUTION: Dynamic DNS is enabled!",
                description="DDNS is active, potentially exposing router location.",
                fix="Disable via '/ip cloud set ddns-enabled=no'"
            ))
        else:
            self.append_output(CheckMetadata(
                result="[+] DDNS is disabled.",
                description="Dynamic DNS is not active.",
                fix=""
            ))

    def check_poe_status(self, connection):
        """Проверка конфигурации PoE - опасность вывода подключенных устройств из строя"""
        self.separator("Checking PoE Status")
        command = "/interface ethernet print detail"
        output = connection.send_command(command)
        risks_found = False
        for interface in output.split("\n\n"):
            name_match = re.search(r'name="([^"]+)"', interface)
            poe_match = re.search(r'poe-out=(\S+)', interface)
            if name_match and poe_match and poe_match.group(1) in ["auto-on", "forced-on"]:
                self.append_output(CheckMetadata(
                    result=f"[!] CAUTION: PoE is enabled on {name_match.group(1)}.",
                    description="Power over Ethernet is active, verify if intended.",
                    fix=f"Disable via '/interface ethernet set {name_match.group(1)} poe-out=off' if not needed."
                ))
                risks_found = True
        if not risks_found:
            self.append_output(CheckMetadata(
                result="[+] No PoE-enabled interfaces detected.",
                description="No interfaces have PoE enabled.",
                fix=""
            ))

    def check_routerboot_protection(self, connection):
        """Проверка защиты загрузки RoS"""
        self.separator("Checking RouterBOOT Protection")
        command = "/system routerboard settings print"
        output = connection.send_command(command)
        if "protected-routerboot: disabled" in output:
            self.append_output(CheckMetadata(
                result="[!] CAUTION: RouterBOOT protection is disabled!",
                description="RouterBOOT is not protected against unauthorized access.",
                fix="Enable via '/system routerboard settings set protected-routerboot=enabled'"
            ))
        else:
            self.append_output(CheckMetadata(
                result="[+] RouterBOOT protection is enabled.",
                description="RouterBOOT is protected.",
                fix=""
            ))

    def check_socks_status(self, connection):
        """Проверка отсутствия несанкционированных прокси"""
        self.separator("Checking SOCKS Proxy Status")
        command = "/ip socks print"
        output = connection.send_command(command)
        if "enabled: yes" in output:
            self.append_output(CheckMetadata(
                result="[!] ALERT: SOCKS proxy is enabled!",
                description="SOCKS proxy is active, potentially allowing unauthorized traffic.",
                fix="Disable via '/ip socks set enabled=no'"
            ))
        else:
            self.append_output(CheckMetadata(
                result="[+] SOCKS proxy is disabled.",
                description="SOCKS proxy is not active.",
                fix=""
            ))

    def check_neighbor_discovery(self, connection):
        """Проверка протоколов обнаружения соседей (CDP, LLDP, MNDP)"""
        self.separator("Checking Neighbor Discovery Protocols")
        command = "/ip neighbor discovery-settings print"
        output = connection.send_command(command)
        if "discover-interface-list: all" in output:
            self.append_output(CheckMetadata(
                result="[!] CAUTION: Discovery protocols on all interfaces!",
                description="Neighbor discovery is enabled on all interfaces.",
                fix="Restrict via '/ip neighbor discovery-settings set discover-interface-list=<specific_list>'"
            ))
        else:
            self.append_output(CheckMetadata(
                result="[+] No security risks in Neighbor Discovery.",
                description="Neighbor discovery is properly configured.",
                fix=""
            ))

    def check_password_length_policy(self, connection):
        """Проверка конфигурации парольной политики (минимальная длина пароля)"""
        self.separator("Checking Password Policy")
        command = "/user settings print"
        output = connection.send_command(command)
        if "minimum-password-length: 0" in output:
            self.append_output(CheckMetadata(
                result="[!] CAUTION: No minimum password length enforced!",
                description="No minimum password length set, weakening security.",
                fix="Set via '/user settings set minimum-password-length=8'"
            ))
        else:
            self.append_output(CheckMetadata(
                result="[+] Password policy is enforced.",
                description="Minimum password length is enforced.",
                fix=""
            ))

    def check_ssh_security(self, connection):
        """Проверка безопасности конфигурации SSH"""
        self.separator("Checking SSH Security")
        command = "/ip ssh print"
        output = connection.send_command(command)
        if "forwarding-enabled: both" in output:
            self.append_output(CheckMetadata(
                result="[!] CAUTION: SSH Dynamic Port Forwarding enabled!",
                description="SSH forwarding is enabled, potentially allowing tunneling.",
                fix="Disable via '/ip ssh set forwarding-enabled=no'"
            ))
        elif "strong-crypto: no" in output:
            self.append_output(CheckMetadata(
                result="[!] CAUTION: Strong crypto is disabled!",
                description="Weak SSH encryption is in use.",
                fix="Enable via '/ip ssh set strong-crypto=yes'"
            ))
        else:
            self.append_output(CheckMetadata(
                result="[+] SSH security settings are proper.",
                description="SSH is configured securely.",
                fix=""
            ))

    def check_connection_tracking(self, connection):
        """Проверка конфигурации отслеживания подключений (конфигурация фейрвола)"""
        self.separator("Checking Connection Tracking")
        command = "/ip firewall connection tracking print"
        output = connection.send_command(command)
        if "enabled: auto" in output or "enabled: on" in output:
            self.append_output(CheckMetadata(
                result="[!] CAUTION: Connection Tracking is enabled!",
                description="Connection tracking is active, may impact performance.",
                fix="Disable via '/ip firewall connection tracking set enabled=no' if not needed."
            ))
        else:
            self.append_output(CheckMetadata(
                result="[+] Connection Tracking is disabled.",
                description="Connection tracking is not active.",
                fix=""
            ))

    def check_romon_status(self, connection):
        """Проверка конфигурации RoMON"""
        self.separator("Checking RoMON Status")
        command = "/tool romon print"
        output = connection.send_command(command)
        if "enabled: yes" in output:
            self.append_output(CheckMetadata(
                result="[!] CAUTION: RoMON is enabled!",
                description="RoMON is active, potentially exposing management access.",
                fix="Disable via '/tool romon set enabled=no'"
            ))
        else:
            self.append_output(CheckMetadata(
                result="[+] RoMON is disabled.",
                description="RoMON is not active.",
                fix=""
            ))

    def check_mac_winbox_security(self, connection):
        """Проверка статуса MAC-сервера - безопасность доступа к управлению через Winbox"""
        self.separator("Checking Winbox MAC Server Settings")
        command = "tool mac-server mac-winbox print"
        output = connection.send_command(command)
        if "allowed-interface-list: all" in output:
            self.append_output(CheckMetadata(
                result="[!] CAUTION: MAC Winbox access on all interfaces!",
                description="Winbox MAC access is unrestricted.",
                fix="Restrict via '/tool mac-server mac-winbox set allowed-interface-list=<specific_list>'"
            ))
        else:
            self.append_output(CheckMetadata(
                result="[+] MAC Winbox is restricted.",
                description="Winbox MAC access is limited to specific interfaces.",
                fix=""
            ))

    def check_snmp(self, connection):
        """Проверка безопасной конфигурации SNMP"""
        self.separator("Checking SNMP Community Strings")
        command = "/snmp community print"
        output = connection.send_command(command)
        bad_names = ["public", "private", "admin", "mikrotik", "root"]
        risks_found = False
        for line in output.splitlines():
            match = re.search(r'^\s*\d+\s+[*X]?\s*([\w-]+)', line)
            if match and match.group(1).lower() in bad_names:
                self.append_output(CheckMetadata(
                    result=f"[!] CAUTION: Weak SNMP community: '{match.group(1)}'",
                    description="Default or weak SNMP community string detected.",
                    fix=f"Change via '/snmp community set {match.group(1)} name=<secure_name>'"
                ))
                risks_found = True
        if not risks_found:
            self.append_output(CheckMetadata(
                result="[+] No weak SNMP community strings.",
                description="No weak SNMP community strings detected.",
                fix=""
            ))

    def check_dst_nat_rules(self, connection):
        """Проверка правил конфигурации правил NAT в файерволе"""
        self.separator("Checking Firewall NAT Rules")
        command = "/ip firewall nat print"
        output = connection.send_command(command)
        dst_nat_rules = [line.strip() for line in output.splitlines() if "action=dst-nat" in line or "action=netmap" in line]
        if dst_nat_rules:
            self.append_output(CheckMetadata(
                result="[!] CAUTION: Destination NAT rules detected!",
                description="Destination NAT rules are present, verify necessity.",
                fix="Review and remove unnecessary rules via '/ip firewall nat remove <number>'"
            ))
            for rule in dst_nat_rules:
                self.append_output(CheckMetadata(
                    result=f"    - {rule}",
                    description="",
                    fix=""
                ))
        else:
            self.append_output(CheckMetadata(
                result="[+] No Destination NAT rules detected.",
                description="No destination NAT rules found.",
                fix=""
            ))

    def detect_malicious_schedulers(self, connection):
        """Проверка отсутствия несанкционированных планировщиков задач"""
        self.separator("Checking for Malicious Schedulers")
        command = "/system scheduler print detail"
        output = connection.send_command(command)

        risks_found = False
        fetch_files = set()

        for task in output.split("\n\n"):
            name_match = re.search(r'name="?([^"]+)"?', task)
            event_match = re.search(r'on-event="?([^"\n]+)"?', task)
            policy_match = re.search(r'policy=([\w,]+)', task)
            interval_match = re.search(r'interval=(\d+)([smhd])', task)

            name = name_match.group(1) if name_match else "Unknown"
            event = event_match.group(1).strip() if event_match else ""
            policy = policy_match.group(1).split(",") if policy_match else []
            interval_value, interval_unit = (int(interval_match.group(1)), interval_match.group(2)) if interval_match else (None, None)

            fetch_match = re.search(r'dst-path=([\S]+)', event)
            if "fetch" in event and fetch_match:
                fetched_file = fetch_match.group(1).strip(";")
                fetch_files.add(fetched_file)
                self.append_output(CheckMetadata(
                    result=f"[!] Noted fetched file: {fetched_file}",
                    description="Scheduler fetches an external file.",
                    fix=""
                ))

            import_match = re.search(r'import\s+([\S]+)', event)
            if "import" in event and import_match:
                imported_file = import_match.group(1).strip(";")
                if imported_file in fetch_files:
                    self.append_output(CheckMetadata(
                        result=f"[!] ALERT: '{name}' is a BACKDOOR!",
                        description=f"This scheduler imports a previously fetched script ({imported_file}). Attacker can inject commands remotely. Interval: {interval_value}{interval_unit}.",
                        fix=f"Remove via '/system scheduler remove {name}'"
                    ))
                    risks_found = True

            dangerous_policies = {"password", "sensitive", "sniff", "ftp"}
            if any(p in dangerous_policies for p in policy):
                self.append_output(CheckMetadata(
                    result=f"[!] ALERT: '{name}' has HIGH PRIVILEGES!",
                    description=f"It has dangerous permissions: {', '.join(policy)}",
                    fix=f"Remove or restrict via '/system scheduler set {name} policy=read,write'"
                ))
                risks_found = True

            if "reboot" in event:
                if interval_value and interval_unit in ["s", "m", "h"] and interval_value < 12:
                    self.append_output(CheckMetadata(
                        result=f"[!] ALERT: '{name}' reboots router TOO FREQUENTLY ({interval_value}{interval_unit})!",
                        description="This may be an attempt to prevent log analysis (anti-forensics).",
                        fix=f"Remove via '/system scheduler remove {name}'"
                    ))
                    risks_found = True
                else:
                    self.append_output(CheckMetadata(
                        result=f"[!] CAUTION: '{name}' schedules a reboot: {event}",
                        description="Ensure this is intentional and not used to hide attacks.",
                        fix=f"Review and adjust via '/system scheduler set {name}' if needed"
                    ))

            if interval_value and interval_unit in ["s", "m", "h"] and interval_value < 25:
                self.append_output(CheckMetadata(
                    result=f"[!] ALERT: '{name}' executes TOO FREQUENTLY ({interval_value}{interval_unit})!",
                    description="This indicates botnet-like persistence.",
                    fix=f"Remove via '/system scheduler remove {name}'"
                ))
                risks_found = True

        if not risks_found:
            self.append_output(CheckMetadata(
                result="[+] No malicious schedulers detected.",
                description="No suspicious schedulers found.",
                fix=""
            ))

    def check_static_dns_entries(self, connection):
        """Проверка несанкционированных статических записей DNS"""
        self.separator("Checking Static DNS Entries")
        command = "/ip dns static print detail"
        output = connection.send_command(command)
        dns_entries = []
        for entry in output.split("\n\n"):
            name_match = re.search(r'name="([^"]+)"', entry)
            address_match = re.search(r'address=([\d.]+)', entry)
            if name_match and address_match:
                dns_entries.append((name_match.group(1), address_match.group(1)))
        if dns_entries:
            self.append_output(CheckMetadata(
                result="[!] WARNING: Static DNS entries exist:",
                description="Static DNS entries detected, verify legitimacy.",
                fix="Remove unnecessary entries via '/ip dns static remove <number>'"
            ))
            for name, address in dns_entries:
                self.append_output(CheckMetadata(
                    result=f"    - {name} -> {address}",
                    description="",
                    fix=""
                ))
        else:
            self.append_output(CheckMetadata(
                result="[+] No static DNS entries found.",
                description="No static DNS entries detected.",
                fix=""
            ))

    def get_router_uptime(self, connection):
        """Проверка времени работы роутера"""
        self.separator("Checking Uptime of Router")
        output = connection.send_command("/system resource print")
        match = re.search(r"uptime:\s*([\w\d\s]+)", output)
        if match:
            uptime_raw = match.group(1)
            time_units = {"w": 0, "d": 0, "h": 0, "m": 0, "s": 0}
            for unit in time_units:
                result = re.search(rf"(\d+){unit}", uptime_raw)
                if result:
                    time_units[unit] = int(result.group(1))
            total_days = time_units["w"] * 7 + time_units["d"]
            self.append_output(CheckMetadata(
                result=f"[*] Router Uptime: {total_days} days, {time_units['h']} hours, {time_units['m']} minutes, {time_units['s']} seconds",
                description="Router uptime retrieved successfully.",
                fix=""
            ))
        else:
            self.append_output(CheckMetadata(
                result="[-] ERROR: Could not retrieve uptime.",
                description="Failed to retrieve router uptime.",
                fix="Check device connectivity or command syntax."
            ))

    def run_inspection(self):
        start_time = time.time()
        try:
            connection = self.connect_to_router()
            checks = {
                "RouterOS Version": self.check_routeros_version,
                "SMB Service": self.check_smb,
                "RMI Services": self.check_rmi_services,
                "Default Users": self.check_default_users,
                "RMI Access": self.checking_access_to_RMI,
                "Wi-Fi Security": self.check_wifi_security,
                "UPnP Status": self.check_upnp_status,
                "DNS Status": self.check_dns_status,
                "DDNS Status": self.check_ddns_status,
                "PoE Status": self.check_poe_status,
                "RouterBOOT Protection": self.check_routerboot_protection,
                "SOCKS Proxy": self.check_socks_status,
                "Neighbor Discovery": self.check_neighbor_discovery,
                "Password Policy": self.check_password_length_policy,
                "SSH Security": self.check_ssh_security,
                "Connection Tracking": self.check_connection_tracking,
                "RoMON Status": self.check_romon_status,
                "MAC Winbox Security": self.check_mac_winbox_security,
                "SNMP Community": self.check_snmp,
                "NAT Rules": self.check_dst_nat_rules,
                "Schedulers": self.detect_malicious_schedulers,
                "Static DNS": self.check_static_dns_entries,
                "Router Uptime": self.get_router_uptime
            }
            if self.full:
                for check in checks.values():
                    check(connection)
            else:
                for check_name in self.selected_checks:
                    checks[check_name](connection)
            connection.disconnect()
            self.append_output(CheckMetadata(f"[*] Disconnected from RouterOS ({self.ip}:{self.port})"))
        except Exception as e:
            self.append_output(CheckMetadata(f"[-] Inspection failed: {e}"))
        end_time = time.time()
        total_time = round(end_time - start_time, 2)
        self.append_output(CheckMetadata(f"[*] All checks completed in {total_time} seconds"))

if __name__ == "__main__":
    try:
        App = RouterOSInspectorApp()
        App.run()
    except Exception as e:
        print(f"An error occurred: {e}")
        input("Press Enter to exit...")