import subprocess
import argparse
import os

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def get_args():
    parser = argparse.ArgumentParser(description="Run enumeration and analysis tasks on specified input file.")
    parser.add_argument('-l', '--input', type=str, required=True, help='Specify the input file path.')
    return parser.parse_args()

def convert_ip_to_domain(file_path: str):
    if os.path.exists("domains.txt"):
        print("domains.txt already exists. Skipping IP to domain conversion.")
        return True
    try:
        # Ensure /usr/bin is in the PATH
        env = os.environ.copy()
        env["PATH"] = "/usr/bin:" + env["PATH"]
        
        # Run the command to convert IPs to domain names and save to domains.txt
        subprocess.run(f"c2i -f {file_path} | hakrevdns -d > domains.txt", shell=True, check=True, env=env)
        print("Conversion completed. The domains are saved in domains.txt.")
    except subprocess.CalledProcessError as e:
        print(f"Error converting IPs: {e}")
        return False
    return True

def run_httpx():
    print(bcolors.OKGREEN + "Formatting Domains" + bcolors.ENDC)
    if os.path.exists("httpdomains.txt"):
        print("httpdomains.txt already exists. Skipping HTTPX scan.")
        return True
    if not os.path.exists("domains.txt"):
        print("domains.txt does not exist. Cannot run HTTPX.")
        return False
    print("Running HTTPX to fetch live HTTP domains...")
    try:
        # Run the httpx command and output to httpdomains.txt
        subprocess.run("cat domains.txt | httpx-toolkit -silent -o httpdomains.txt", shell=True, check=True)
        print("HTTPX scan completed. Results are saved in httpdomains.txt.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error running HTTPX: {e}")
        return False

def run_katana():
    print(bcolors.OKGREEN + "Running Passive Katana Crawl" + bcolors.ENDC)
    if os.path.exists("allurls.txt"):
        print("allurls.txt already exists. Skipping Katana.")
        return True
    if not os.path.exists("domains.txt"):
        print("domains.txt does not exist. Cannot run Katana.")
        return False
    try:
        # Run the katana tool with specified arguments
        subprocess.run(
            "katana -u domains.txt -d 5 -ps -pss waybackarchive,commoncrawl,alienvault -kf -jc -fx -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg -silent > allurls.txt",
            shell=True,
            check=True
        )
        print("Katana completed. The URLs are saved in allurls.txt.")
    except subprocess.CalledProcessError as e:
        print(f"Error running katana: {e}")
        return False
    return True

def run_additional_katana():
    print(bcolors.OKGREEN + "Running Active Katana Crawl" + bcolors.ENDC)
    if os.path.exists("katanacrawl.txt"):
        print("katanacrawl.txt already exists. Skipping additional Katana crawl.")
        return True
    if not os.path.exists("domains.txt"):
        print("domains.txt does not exist. Cannot run additional Katana crawl.")
        return False
    try:
        # Run the additional katana command
        subprocess.run("katana -list domains.txt -silent > katanacrawl.txt", shell=True, check=True)
        print("Additional Katana crawl completed. The results are saved in katanacrawl.txt.")
    except subprocess.CalledProcessError as e:
        print(f"Error running additional katana crawl: {e}")
        return False
    return True

def filter_urls():
    print(bcolors.OKGREEN + "Filtering URLs" + bcolors.ENDC)
    if not os.path.exists("allurls.txt") and not os.path.exists("katanacrawl.txt"):
        print("Neither allurls.txt nor katanacrawl.txt exist. Cannot filter URLs.")
        return False

    files_to_check = {
        "alljs.txt": r'grep -E "\.js$"',
        "interesting_files.txt": r'grep -E "\.txt|\.log|\.cache|\.secret|\.db|\.backup|\.yml|\.json|\.gz|\.rar|\.zip|\.config"'
    }
    
    for output_file, grep_command in files_to_check.items():
        with open(output_file, "a") as outfile:  # Open in append mode
            for source_file in ["allurls.txt", "katanacrawl.txt"]:
                if os.path.exists(source_file):
                    try:
                        subprocess.run(f"{grep_command} {source_file}", shell=True, stdout=outfile, check=True)
                    except subprocess.CalledProcessError as e:
                        if e.returncode != 1:  # Allow grep not matching any lines, but catch other errors
                            print(f"Error filtering {source_file} for {output_file}: {e}")
                        else:
                            print(f"No matches found in {source_file} for {output_file}, continuing...")
    return True


def run_gf_commands():
    print(bcolors.OKGREEN + "Running GF" + bcolors.ENDC)
    if not os.path.exists("allurls.txt") and not os.path.exists("katanacrawl.txt"):
        print("Neither allurls.txt nor katanacrawl.txt exist. Cannot run GF commands.")
        return False

    gf_commands = {
        "allxss.txt": "gf xss",
        "alllfi.txt": "gf lfi",
        "allredirect.txt": "gf redirect",
        "allpotential.txt": "gf potential",
        "allrce.txt": "gf rce"
    }
    for output_file, gf_command in gf_commands.items():
        with open(output_file, "a") as output:  # Open in append mode
            for source_file in ["allurls.txt", "katanacrawl.txt"]:
                if os.path.exists(source_file):
                    try:
                        subprocess.run(f"cat {source_file} | {gf_command}", shell=True, stdout=output, check=True)
                    except subprocess.CalledProcessError as e:
                        print(f"Error running gf command on {source_file} for {output_file}: {e}")
            print(f"GF command '{gf_command}' completed. The filtered results are saved in {output_file}.")

    return True

def run_nuclei_on_domains():
    print(bcolors.OKGREEN + "Finding Web Technologies" + bcolors.ENDC)
    if os.path.exists("tech.txt"):
        print("tech.txt already exists. Skipping Nuclei analysis.")
        return True
    if not os.path.exists("domains.txt"):
        print("domains.txt does not exist. Cannot run nuclei.")
        return False
    try:
        # Run the nuclei command with specified tags and output to tech.txt
        subprocess.run("cat domains.txt | nuclei -silent -tags cves,osint,tech > tech.txt", shell=True, check=True)
        print("Nuclei analysis completed. Results are saved in tech.txt.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error running nuclei: {e}")
        return False

# Being exploitation >:)

def run_subdominator():
    print(bcolors.OKGREEN + "Running Subdominator" + bcolors.ENDC)
    if os.path.exists("subdomain_takeover_results.txt"):
        print("subdomain_takeover_results.txt already exists. Skipping subdomain takeover testing.")
        return True
    if not os.path.exists("domains.txt"):
        print("domains.txt does not exist. Cannot run subzy for subdomain takeover testing.")
        return False
    try:
        # Run the subzy command for testing subdomain takeover
        subprocess.run("subdominator -l domains.txt > subdomain_takeover_results.txt", shell=True, check=True)
        print("Subdomain takeover testing completed. Results are saved in subdomain_takeover_results.txt.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error running subdominator for subdomain takeover testing: {e}")
        return False

def run_corsy():
    print(bcolors.OKGREEN + "Running Corsy" + bcolors.ENDC)
    if os.path.exists("corsy_results.txt"):
        print("corsy_results.txt already exists. Skipping CORS scan.")
        return True
    if not os.path.exists("domains.txt"):
        print("httpdomains.txt does not exist. Cannot run corsy.")
        return False
    print("Running corsy for CORS vulnerability scanning...")
    try:
        # Build the corsy command with headers
        command = '''corsy -i httpdomains.txt -t 10 --headers "User-Agent: GoogleBot\nCookie: SESSION=SYNACK" > corsy_results.txt'''
        subprocess.run(command, shell=True, check=True)
        print("CORS scan completed. Results are saved in corsy_results.txt.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error running corsy: {e}")
        return False

def run_secret_finder():
    print(bcolors.OKGREEN + "Running Secret Finder" + bcolors.ENDC)
    if not os.path.exists("alljs.txt"):
        print("alljs.txt does not exist. Cannot run SecretFinder.")
        return False
    if os.path.exists("secret.txt"):
        print("secret.txt already exists.")
        return True
    
    try:
        with open("alljs.txt", "r") as file:
            for url in file:
                url = url.strip()
                if url:
                    command = f"python3 /home/kali/tools/SecretFinder/SecretFinder.py -e -i {url} -o cli"
                    # Append output to secret.txt
                    with open("secret.txt", "a") as outfile:
                        subprocess.run(command, shell=True, stdout=outfile, stderr=subprocess.STDOUT, timeout=60)
        print("SecretFinder execution completed for all URLs in alljs.txt.")
        return True
    except subprocess.TimeoutExpired:
        print("Secret Finder Timed Out. Process did not complete within the allocated time.")
        return False
    except subprocess.CalledProcessError as e:
        print(f"Error running SecretFinder: {e}")
        return False
    except Exception as e:
        print(f"An error occurred: {e}")
        return False

    
def main(args):
    args = get_args()
    input_file = args.input

    banner = """
████████╗██╗  ██╗███████╗    ██████╗  ██████╗  ██████╗ ██████╗     ███╗   ███╗ █████╗ ███╗   ██╗███████╗    
╚══██╔══╝██║  ██║██╔════╝    ██╔══██╗██╔═══██╗██╔═══██╗██╔══██╗    ████╗ ████║██╔══██╗████╗  ██║██╔════╝    
   ██║   ███████║█████╗      ██████╔╝██║   ██║██║   ██║██████╔╝    ██╔████╔██║███████║██╔██╗ ██║███████╗    
   ██║   ██╔══██║██╔══╝      ██╔═══╝ ██║   ██║██║   ██║██╔══██╗    ██║╚██╔╝██║██╔══██║██║╚██╗██║╚════██║    
   ██║   ██║  ██║███████╗    ██║     ╚██████╔╝╚██████╔╝██║  ██║    ██║ ╚═╝ ██║██║  ██║██║ ╚████║███████║    
   ╚═╝   ╚═╝  ╚═╝╚══════╝    ╚═╝      ╚═════╝  ╚═════╝ ╚═╝  ╚═╝    ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝    
██████╗ ██╗   ██╗ ██████╗     ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗                   
██╔══██╗██║   ██║██╔════╝     ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗                  
██████╔╝██║   ██║██║  ███╗    ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝                  
██╔══██╗██║   ██║██║   ██║    ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗                  
██████╔╝╚██████╔╝╚██████╔╝    ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║                  
╚═════╝  ╚═════╝  ╚═════╝     ╚══════╝╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝                  
                                                                                                             
                                     By Grizzly (Kryp7os) 2024                                                                       """
    print(banner)

    print(f"{bcolors.HEADER}Starting the enumeration process using input file: {input_file}{bcolors.ENDC}")

    # Step 1: Convert IPs to domain names
    if not convert_ip_to_domain(input_file):
        print("Conversion to domain names did not complete successfully. Exiting.")
        return

    # Step 1a: Convert domains to http
    if not run_httpx():
        print("HTTPX command did not complete successfully. Exiting.")
        return

    # Step 2: Run Katana
    if not run_katana():
        print("Katana step did not complete successfully. Exiting.")
        return

    # Step 3: Run Additional Katana
    if not run_additional_katana():
        print("Additional Katana crawl did not complete successfully. Exiting.")
        return

    # Step 4: Filter URLs
    if not filter_urls():
        print("URL filtering did not complete successfully. Exiting.")
        return

    # Step 5: Run GF commands
    if not run_gf_commands():
        print("GF commands did not complete successfully. Exiting.")
        return

    #Step 6: Run Nuclei
    if not run_nuclei_on_domains():
        print("Nuclei command did not complete successfully. Exiting.")
        return

    #Step 7: Run Subzy
    if not run_subdominator():
        print("Subdominator command did not complete successfully. Exiting.")
        return
    
    #Step 8: Run Corsy
    if not run_corsy():
        print("Corsy command did not complete successfully. Exiting.")
        return

    #Step 9: Run secret_finder
    if not run_secret_finder():
        print("SecretFinder command did not complete successfully. Exiting.")
        return

    print(bcolors.BOLD + "All tasks completed successfully! :)" + bcolors.ENDC)

if __name__ == "__main__":
    args = get_args()
    main(args)
