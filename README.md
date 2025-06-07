
---

# Open-Source SOC Stack with Docker  
*Unified SIEM, Threat Intelligence, Incident Response & Automation*  

---

## 🌟 Overview  
This repository deploys a full Security Operations Center (SOC) stack using Docker, including:  
- **Wazuh**: Endpoint security & SIEM .  
- **TheHive**: Incident response platform .  
- **MISP**: Threat intelligence sharing .  
- **Shuffle**: Security automation & orchestration .  

---

## ⚙️ Prerequisites  
1. **Docker & Docker Compose** installed.  
2. **Minimum Resources**:  
   - 8 vCPU, 16 GB RAM, 100 GB storage (adjust per [Wazuh’s scaling guide](https://documentation.wazuh.com/current/quickstart.html#requirements) .  
3. **Linux host** (Ubuntu 22.04 recommended) .  

---

## 🐳 Docker Deployment 
**Important :** To ensure seamless integration and communication between all security tools (including MISP, Wazuh,TheHive, and Shuffle) within our Docker environment, it is imperative that each tool operates under a common Docker network. 
This unified network, designated as "Soc_net", will facilitate inter-container communication and enable efficient data sharing and workflow orchestration across the platform. 
Consequently, the configuration for this network, "Soc_net", must be explicitly defined and included within the docker-compose.yml file for each respective tool to ensure they are all connected to this shared infrastructure.
```bash 
docker network create SOC_NET
```
### 1. Wazuh (XDR/SIEM)  
**Official Setup**:  
```bash  
git clone https://github.com/wazuh/wazuh-docker.git -b v4.12.0 
```
```bash  
cd wazuh-docker/single-node && docker-compose -f generate-indexer-certs.yml run --rm generator 
```
```bash  
docker-compose up
```
**Wazuh Dashboard**: Login to `https://127.0.0.1:9443`

-   User: `admin`
-   Password: `SecretPassword`
---

### 2. TheHive (Incident Response)  +  MISP (Threat Intelligence)
```bash
git clone https://github.com/MISP/misp-docker 
```
-   Copy the `template.env` to `.env`
-   Customize `.env` based on your needs (optional step). Only changed BASE_URL to https://misp.local

	```bash  
	docker compose up 
	```
**MISP**: Login to `https://127.0.0.1:8443`

-   User: `admin@admin.test`
-   Password: `admin`

**TheHive**: Login to `http://127.0.0.1:9000`

-   User: `admin`
-   Password: `secret`
---

### 3. Shuffle (Automation)  
**Official Setup**:  
 -  Make sure you have [Docker](https://docs.docker.com/get-docker/) installed, and that you have a minimum of **2Gb of RAM** available.
 -  Download Shuffle
	```bash
	git clone https://github.com/Shuffle/Shuffle
	cd Shuffle
	```
 -  Fix prerequisites for the Opensearch database (Elasticsearch):
	```bash
	mkdir shuffle-database                    # Create a database folder
	sudo chown -R 1000:1000 shuffle-database  # IF you get an error using 'chown', add the user first with 'sudo useradd opensearch'
	sudo swapoff -a                           # Disable swap
	```
 -  Run docker-compose.
	```bash
	docker-compose up -d
	```
 -  Recommended for Opensearch to work well
	```bash
	sudo sysctl -w vm.max_map_count=262144
	```
**Shuffle**: Login to `https://127.0.0.1:3443`

---
##  Caddy Setup

**What is Caddy?**
Caddy is a modern, open-source web server and reverse proxy written in Go. It automates
SSL/TLS certificates and lets you access services via domain names without specifying ports
in URLs.

**Steps to Set Up Caddy**
```bash
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update && sudo apt install caddy
```
**Configure Caddyfile**
Edit /etc/caddy/Caddyfile:

    # Global HTTPS settings (auto-HTTPS for domains)
    {
        # Optional: Use a self-signed certificate for local domains
        local_certs
    }
    
    # Wazuh Dashboard (HTTPS)
    wazuh.dashboard {
        reverse_proxy https://127.0.0.1:9443 {
            # Disable TLS verification if Wazuh uses a self-signed cert
            transport http {
                tls_insecure_skip_verify
            }
        }
    }
    
    # MISP (HTTPS)
    misp.local {
        reverse_proxy https://127.0.0.1:8443 {
            transport http {
                tls_insecure_skip_verify
            }
        }
    }
    
    # TheHive (HTTP)
    thehive.local {
        reverse_proxy http://127.0.0.1:9000
    }
    
    # Shuffle (HTTPS)
    shuffle.local {
        reverse_proxy https://127.0.0.1:3443 {
            transport http {
                tls_insecure_skip_verify
            }
        }
    }
**Update /etc/hosts**

 - Map domains to 127.0.0.1:
	```bash
	sudo nano /etc/hosts
	```
 - Add: 
	```
	127.0.0.1	misp.local
	127.0.0.1	wazuh.dashboard
	127.0.0.1	thehive.local
	127.0.0.1	shuffle.local
	```
 - then
	 ```bash
	sudo systemctl restart caddy
	```
---
## 🔗 Integration Guide  
1. **Wazuh → TheHive**:  
   - Use Wazuh’s webhook to forward alerts to TheHive’s API .  
2. **MISP → TheHive**:  
   - Sync threat feeds using TheHive’s MISP synchronization module .  
3. **Shuffle Automation**:  
   - Deploy workflows to auto-create TheHive cases from Wazuh alerts .  

---

## 🚀 Usage  
1. Start all services one by one:  
   ```bash  
   docker-compose up -d  
   ```  
2. Access dashboards:  
   | Tool       | URL                          | Default Credentials       |  
   |------------|------------------------------|---------------------------|  
   | **Wazuh**  | `https://wazuh.dashboard`          | `admin:SecretPassword`  |  
   | **TheHive**| `http://thehive.local`      | `admin:secret` |  
   | **MISP**   | `https://misp.local`          | `admin@admin.test:admin`  |  
   | **Shuffle**| `https://shuffle.local`      | (Set on first run)        |  



---

## ⚠️ Important Notes  
1. **Resource Allocation**:  
   - Wazuh Indexer requires heavy CPU/RAM for large agent counts .  
2. **Persistence**:  
   - Mount volumes for `/var/lib/cassandra` (TheHive), `/var/www/MISP` (MISP), and Wazuh indexer data.  
3. **Updates**:  
   - Disable auto-updates for Wazuh to avoid breaking changes (`sed -i "s/^enabled=1/enabled=0/" /etc/yum.repos.d/wazuh.repo`) .  

---

## 🔧 Troubleshooting  
- **MISP Entropy Errors**: Install `rng-tools` to fix entropy shortages during setup .  
- **Wazuh Dashboard Issues**: Increase system resources if the dashboard fails to load .  
- **TheHive-Cassandra Connectivity**: Verify `cassandra.yaml` seed configuration .  

---

## 📚 References  
- [Wazuh Official Docs](https://documentation.wazuh.com/current/installation-guide/index.html)   
- [TheHive Installation Guide](https://docs.strangebee.com/thehive/installation/step-by-step-installation-guide/)   
- [MISP Docker Guide](https://www.misp-project.org/download/)   
- [Shuffle GitHub](https://github.com/Shuffle/Shuffle)   

---

**Contribute**: Issues/PRs welcome! Always refer to official docs for critical updates.  
**License**: Apache 2.0 (excluding MISP, which uses AGPLv3).  

> **Warning**: This setup is for lab use. Harden configurations for production!  

--- 

For detailed configurations (e.g., SSL, clustering), see each tool’s documentation linked above.

