Recon-A is an open-source intelligence tool that makes it easier to verify existing domains, subdomains and open ports.

Requirements:

OS: Linux, Debian based distribution

python libraries:
  -pip install dnspython-
  -pip install requests-
  -pip install python-nmap-
  -pip install pathlib-
  -pip install csv-
  -pip install pathlib-

For screenshots, a subprocess is used called wkhtmltopdf & wkhtmltoimage for Debian based distributions (Debian 11 / Debian 10 / Debian 9)

  sudo apt update
  sudo apt -y install wget
  wget     https://github.com/wkhtmltopdf/wkhtmltopdf/releases/download/0.12.5/wkhtmltox_0.12.5-1.stretch_amd64.deb
  sudo dpkg -i wkhtmltox_0.12.5-1.stretch_amd64.deb
  sudo apt -f install
  
To run: Runs directly from saved file. Input company name when prompted. 
  
Screenshots are saved under found domain_name.png. 
