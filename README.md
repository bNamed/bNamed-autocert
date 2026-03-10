# bNamed AutoCert

`bNamed-autocert.sh` is a small Bash utility that automatically requests and retrieves SSL certificates from the **bNamed API**, writes them to disk, and safely updates existing certificate files.

The script is designed to be:

- **Simple** – minimal dependencies
- **Safe** – existing certificates are only replaced if the new certificate was successfully obtained
- **Flexible** – supports separate key/certificate files or a combined `.pem`
- **Automatable** – exits with proper status codes so it can be used in cron, monit, or scripts

---

# Requirements

The script requires:

- bash
- curl
- xmllint (libxml2-utils)

Install xmllint if necessary.

Debian / Ubuntu:

    apt install libxml2-utils

RHEL / Rocky / Alma:

    dnf install libxml2

---

# DNS Validation Requirement

Before a certificate can be issued, the domain must be prepared for **automatic DNS validation**.

The client must create a **CNAME record**:

    _dnsauth.yourname.be

pointing to the target provided in their **bNamed account dashboard**.

To find the exact CNAME value:

1. Log in to your **bNamed account dashboard**
2. Below **Services** click **SSL certificates**
3. The required `_dnsauth` CNAME target will be shown there

Once this DNS record exists, certificate requests for that domain can complete automatically.

Example DNS record:

    _dnsauth.yourname.be  CNAME  some-validation-target.acme-challenge.be.

---

# Installation

Clone the repository:

    git clone https://github.com/YOURACCOUNT/bnamed-autocert.git
    cd bnamed-autocert

Make the script executable:

    chmod +x bNamed-autocert.sh

---

# Configuration

Create a configuration file containing your API credentials.

Example `bNamed-autocert.conf`:

    APIUID="YOURUID"
    APIKEY="YOURPWD"

    # Optional defaults
    #CN="www.yourname.be"
    #PRIVKEY_PATH="/usr/share/nginx/yourname.be.key"
    #FULLCHAIN_PATH="/usr/share/nginx/yourname.be.crt"

    # Optional combined PEM file
    #COMBINED_PEM_PATH="/usr/share/nginx/yourname.be.pem"

Permissions should restrict access to this file:

    chmod 600 bNamed-autocert.conf

---

# Usage

Example usage on a server running nginx:

    ./bNamed-autocert.sh --config ./bNamed-autocert.conf \
      --cn "www.yourname.be" \
      --privkey /usr/share/nginx/yourname.be.key \
      --fullchain /usr/share/nginx/yourname.be.crt \
      && nginx -t && nginx -s reload

If certificate retrieval fails, the script exits with a non-zero status and the nginx reload will **not** be executed.

---

# Combined PEM Output

Some systems require a single `.pem` file containing:

1. Private key
2. Certificate
3. Certificate chain

You can generate such a file with:

    --combined-pem /usr/share/nginx/yourname.be.pem

Example:

    ./bNamed-autocert.sh --config ./bNamed-autocert.conf \
      --cn "www.yourname.be" \
      --combined-pem /usr/share/nginx/yourname.be.pem

You may also generate both separate files and a combined file at the same time.

---

# How It Works

1. The script calls `requestAutoCert` via the bNamed API
2. If another request is already pending (`ErrorCode=19901`), the script waits 10 minutes and retries once
3. The script polls the API until the certificate status becomes `completed`
4. Temporary files are created
5. Existing certificate files are backed up
6. New certificate files are installed

This ensures services like nginx never see incomplete certificate files.

---

# Backup Behaviour

Whenever a certificate file is replaced, the previous version is preserved with a timestamp.

Example:

    yourname.be.key.20260310T142030Z.bak
    yourname.be.crt.20260310T142030Z.bak

---

The script will request a new certificate even if the current certificate doesn't need to be replaced yet. So only run it near the current expiration date of your certificate. We do plan in future versions to include a check on the expiration date to only run when needed. 


