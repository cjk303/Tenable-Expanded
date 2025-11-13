# AWX Tenable/Nessus Agent Deployment Playbook

This repository contains an **Ansible playbook** to deploy Tenable/Nessus Agents on Linux hosts (RHEL 7/8/9, Debian/Ubuntu) via **AWX**. The playbook is AWX-safe, shell-based, and uses a **hardcoded activation key** for agent linking.

---

## Table of Contents

- [Overview](#overview)  
- [AWX Survey Setup](#awx-survey-setup)  
- [Playbook Usage](#playbook-usage)  
- [Variables](#variables)  
- [API Examples](#api-examples)  
- [Debugging](#debugging)  

---

## Overview

This playbook supports:

- Dynamic inventory from AWX survey input (`dynamic_targets`) or static inventory (`agents` group).  
- RHEL 7/8/9 installation via shell (`yum`/`dnf`).  
- Debian/Ubuntu installation via shell (`dpkg -i`).  
- Force relink option to unlink existing Nessus agent.  
- Hardcoded activation key to avoid template errors in AWX.  
- AWX-safe handling of PAM credentials.  
- Installation and link status reporting per host.  

---

## AWX Survey Setup

To run this playbook via AWX **Job Template Survey**, add the following variables:

| Variable | Type | Default / Notes |
|----------|------|----------------|
| `host_source` | Multiple Choice | `awx` (options: `awx`, `dynamic`) |
| `target_hosts` | Text | Comma-separated hosts, used if `host_source = dynamic` |
| `pam_source` | Multiple Choice | `vault` (options: `vault`, `survey`) |
| `pam_user` | Text | Required if `pam_source = survey` |
| `pam_pass` | Password | Required if `pam_source = survey` |
| `escalation_method` | Text | Default: `sudo` |
| `force_relink` | Multiple Choice | `true` (options: `true`, `false`) |

**Notes:**

- `activation_key` is **hardcoded in the playbook**: no survey input required.  
- Survey validation is handled in the playbook (PAM credentials check).  
- For dynamic hosts, `target_hosts` must be a comma-separated string.  

---

## Playbook Usage

Run via AWX job template or CLI:

```bash
ansible-playbook tenable_agent.yml
Dynamic host example (via extra_vars):

bash
Copy code
ansible-playbook tenable_agent.yml \
  -e "host_source=dynamic target_hosts=host1,host2 pam_source=survey pam_user=root pam_pass=MyPassword force_relink=true"
Variables
Hardcoded in the playbook:

yaml
Copy code
vars:
  activation_key: "YOUR_HARDCODED_TENABLE_KEY_HERE"
  force_relink: "{{ force_relink | default(true) }}"
  ansible_become_method: "{{ escalation_method | default('sudo') }}"
  ansible_ssh_user: "{{ pam_user if pam_source == 'survey' else omit }}"
  ansible_ssh_pass: "{{ pam_pass if pam_source == 'survey' else omit }}"
Host OS detection:

RHEL 7 → yum -y localinstall /tmp/el7.rpm

RHEL 8/9 → dnf -y localinstall /tmp/el8.rpm / el9.rpm

Debian/Ubuntu → dpkg -i /tmp/NessusAgent-10.9.0-ubuntu1604_amd64.deb || apt-get install -f -y

API Examples
1. Get API token
bash
Copy code
curl -k -X POST "https://lnxawx.amer.epiqcorp.com/api/v2/tokens/" \
  -H "Content-Type: application/json" \
  -d '{"username":"YOUR_USERNAME","password":"YOUR_PASSWORD"}'
2. List Job Templates
bash
Copy code
curl -k -H "Authorization: Bearer YOUR_TOKEN" \
  "https://lnxawx.amer.epiqcorp.com/api/v2/job_templates/"
3. Launch Tenable Job Template
bash
Copy code
curl -k -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{
        "extra_vars": {
          "host_source": "dynamic",
          "target_hosts": "host1,host2",
          "pam_source": "survey",
          "pam_user": "root",
          "pam_pass": "MyPassword",
          "escalation_method": "sudo",
          "force_relink": true
        }
      }' \
  "https://lnxawx.amer.epiqcorp.com/api/v2/job_templates/JOB_TEMPLATE_ID/launch/"
4. Check Job Status
bash
Copy code
curl -k -H "Authorization: Bearer YOUR_TOKEN" \
  "https://lnxawx.amer.epiqcorp.com/api/v2/jobs/JOB_ID/"
5. Get Job Output
bash
Copy code
curl -k -H "Authorization: Bearer YOUR_TOKEN" \
  "https://lnxawx.amer.epiqcorp.com/api/v2/jobs/JOB_ID/stdout/?format=txt"
Debugging Tips
Use no_log: true in debug tasks for PAM credentials.

If installation fails, check /tmp/el*.rpm or /tmp/NessusAgent*.deb exist.

Force relink can cause harmless failures if the agent was not linked before.

Ensure your RPM/DEB files match the host OS version.

