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
            email_matches = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', output)
            emails_found = len(email_matches)

            # Improved host extraction
            host_matches = re.findall(r'\b(?:[a-zA-Z0-9-]+\.)+(?:[a-zA-Z]{2,})\b', output)
            email_domains = set(email.split('@')[1] for email in email_matches)
            host_only = [host for host in host_matches if host not in email_domains]
            hosts_found = len(set(host_only))

            total_ips += ips_found
            total_emails += emails_found
            total_hosts += hosts_found

            summary = f"IPs Found: {ips_found}, Emails Found: {emails_found}, Hosts Found: {hosts_found}\n"
            separator = "=" * 50
            print(summary)
            print(separator)
            f.write(summary + "\n")

            # Write the actual email addresses found
            if email_matches:
                f.write("Email Addresses Found:\n")
                for email in sorted(set(email_matches)):
                    f.write(f"- {email}\n")
                f.write("\n")

            # Write the actual hostnames found
            if host_only:
                f.write("Hostnames Found:\n")
                for host in sorted(set(host_only)):
                    f.write(f"- {host}\n")
                f.write("\n")

            f.write(separator + "\n\n")

    final_summary = (
        f"Total IPs Found: {total_ips}\n"
        f"Total Emails Found: {total_emails}\n"
        f"Total Hosts Found: {total_hosts}\n"
    )
    with open(output_file, "a") as f:
        f.write(final_summary)

if __name__ == "__main__":
    domain = "daffodilvarsity.edu.bd"
    limit = 200
    output_file = "theharvester_output.txt"
    sources = [
        "anubis", "baidu", "bevigil", "binaryedge", "bing", "bingapi", "bufferoverun", "brave", "censys", "certspotter", "criminalip", "crtsh", "dnsdumpster",
        "duckduckgo", "fullhunt", "github-code", "hackertarget", "hunter", "hunterhow", "intelx", "netlas", "onyphe", "otx", "pentesttools", "projectdiscovery",
        "rapiddns", "rocketreach", "securityTrails", "sitedossier", "subdomaincenter", "subdomainfinderc99", "threatminer", "tomba", "urlscan", "virustotal",
        "yahoo", "zoomeye"
    ]
    run_theHarvester(domain, limit, sources, output_file)
