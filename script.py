import subprocess
import re

def run_theHarvester(domain, limit, sources, output_file):
    total_ips = 0
    total_emails = 0
    total_hosts = 0
    
    with open(output_file, "w") as f:
        for source in sources:
            command = ["sudo", "theHarvester", "-d", domain, "-l", str(limit), "-b", source]
            print(f"Running: {' '.join(command)}")
            f.write(f"Running: {' '.join(command)}\n")
            result = subprocess.run(command, capture_output=True, text=True)
            output = result.stdout + "\n" + result.stderr
            f.write(output + "\n")
            print(f"Finished: {source}\n")
            f.write(f"Finished: {source}\n\n")
            
            # Count IPs, emails, and hosts
            ips_found = len(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', output))
            emails_found = len(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', output))
            hosts_found = len(re.findall(r'Host: \S+', output))
            
            total_ips += ips_found
            total_emails += emails_found
            total_hosts += hosts_found
            
            summary = f"IPs Found: {ips_found}, Emails Found: {emails_found}, Hosts Found: {hosts_found}\n"
            separator = "=" * 50  # Design separator
            print(summary)
            print(separator)  # Print separator
            f.write(summary + "\n")
            f.write(separator + "\n\n")  # Write separator
    
    final_summary = f"Total IPs Found: {total_ips}\nTotal Emails Found: {total_emails}\nTotal Hosts Found: {total_hosts}\n"
    with open(output_file, "a") as f:
        f.write(final_summary)

if __name__ == "__main__":
    domain = "daffodilvarsity.edu.bd/"
    limit = 200
    output_file = "theharvester_output.txt"
    sources = [
        "anubis", "baidu", "bevigil", "binaryedge", "bing", "bingapi", "bufferoverun", "brave", "censys", "certspotter", "criminalip", "crtsh", "dnsdumpster",
        "duckduckgo", "fullhunt", "github-code", "hackertarget", "hunter", "hunterhow", "intelx", "netlas", "onyphe", "otx", "pentesttools", "projectdiscovery",
        "rapiddns", "rocketreach", "securityTrails", "sitedossier", "subdomaincenter", "subdomainfinderc99", "threatminer", "tomba", "urlscan", "virustotal",
        "yahoo", "zoomeye"
    ]
    run_theHarvester(domain, limit, sources, output_file)