---
- name: Deploy Nessus Agent
  hosts: agents
  gather_facts: no
  vars:
    force_relink: true
    ansible_remote_tmp: /tmp
    ansible_become_flags: "-S -tt"

  pre_tasks:
    - name: Gather minimal OS facts
      setup:
        gather_subset:
          - '!all'
          - 'min'

  tasks:

    # ---------------- Remove Rapid7 ----------------
    - name: Upload Rapid7 remover as normal user
      copy:
        src: "r7remover.sh"
        dest: /tmp/r7remover.sh
        mode: "0755"
      become: no
      when: remove_rapid7 | bool

    - name: Run Rapid7 remover script with dzdo/sudo
      shell: |
        {% if ansible_become_method == 'dzdo' %}
        echo {{ ansible_become_password | quote }} | dzdo -S /bin/bash /tmp/r7remover.sh
        {% else %}
        echo {{ ansible_become_password | quote }} | sudo -S /bin/bash /tmp/r7remover.sh
        {% endif %}
      when: remove_rapid7 | bool

    # ---------------- Remove existing Nessus token ----------------
    - name: Remove existing Nessus token if force_relink
      shell: |
        {% if ansible_become_method == 'dzdo' %}
        echo {{ ansible_become_password | quote }} | dzdo -S /opt/nessus_agent/sbin/nessuscli agent unlink || true
        {% else %}
        echo {{ ansible_become_password | quote }} | sudo -S /opt/nessus_agent/sbin/nessuscli agent unlink || true
        {% endif %}
      when: force_relink

    # ---------------- RHEL 7 ----------------
    - name: Upload RHEL 7 package as normal user
      copy:
        src: "el7.rpm"
        dest: "/tmp/el7.rpm"
        mode: '0755'
      become: no
      when:
        - ansible_facts['distribution'] == "RedHat"
        - ansible_facts['distribution_major_version'] == "7"

    - name: Install RHEL 7 package
      shell: |
        {% if ansible_become_method == 'dzdo' %}
        echo {{ ansible_become_password | quote }} | dzdo -S yum -y localinstall /tmp/el7.rpm
        {% else %}
        echo {{ ansible_become_password | quote }} | sudo -S yum -y localinstall /tmp/el7.rpm
        {% endif %}
      when:
        - ansible_facts['distribution'] == "RedHat"
        - ansible_facts['distribution_major_version'] == "7"

    # ---------------- RHEL 8 ----------------
    - name: Upload RHEL 8 package as normal user
      copy:
        src: "el8.rpm"
        dest: "/tmp/el8.rpm"
        mode: '0755'
      become: no
      when:
        - ansible_facts['distribution'] == "RedHat"
        - ansible_facts['distribution_major_version'] == "8"

    - name: Install RHEL 8 package
      shell: |
        {% if ansible_become_method == 'dzdo' %}
        echo {{ ansible_become_password | quote }} | dzdo -S dnf -y localinstall /tmp/el8.rpm
        {% else %}
        echo {{ ansible_become_password | quote }} | sudo -S dnf -y localinstall /tmp/el8.rpm
        {% endif %}
      when:
        - ansible_facts['distribution'] == "RedHat"
        - ansible_facts['distribution_major_version'] == "8"

    # ---------------- RHEL 9 ----------------
    - name: Upload RHEL 9 package as normal user
      copy:
        src: "el9.rpm"
        dest: "/tmp/el9.rpm"
        mode: '0755'
      become: no
      when:
        - ansible_facts['distribution'] == "RedHat"
        - ansible_facts['distribution_major_version'] == "9"

    - name: Install RHEL 9 package
      shell: |
        {% if ansible_become_method == 'dzdo' %}
        echo {{ ansible_become_password | quote }} | dzdo -S dnf -y localinstall /tmp/el9.rpm
        {% else %}
        echo {{ ansible_become_password | quote }} | sudo -S dnf -y localinstall /tmp/el9.rpm
        {% endif %}
      when:
        - ansible_facts['distribution'] == "RedHat"
        - ansible_facts['distribution_major_version'] == "9"

    # ---------------- Debian/Ubuntu ----------------
    - name: Upload Debian/Ubuntu package as normal user
      copy:
        src: "NessusAgent-10.9.0-ubuntu1604_amd64.deb"
        dest: "/tmp/NessusAgent-10.9.0-ubuntu1604_amd64.deb"
        mode: '0755'
      become: no
      when: ansible_facts['distribution'] in ['Ubuntu', 'Debian']

    - name: Install Debian/Ubuntu package
      shell: |
        {% if ansible_become_method == 'dzdo' %}
        echo {{ ansible_become_password | quote }} | dzdo -S apt-get install -y /tmp/NessusAgent-10.9.0-ubuntu1604_amd64.deb
        {% else %}
        echo {{ ansible_become_password | quote }} | sudo -S apt-get install -y /tmp/NessusAgent-10.9.0-ubuntu1604_amd64.deb
        {% endif %}
      when: ansible_facts['distribution'] in ['Ubuntu', 'Debian']

    # ---------------- Start & Link Nessus Agent ----------------
    - name: Enable and start Nessus Agent
      shell: |
        {% if ansible_become_method == 'dzdo' %}
        echo {{ ansible_become_password | quote }} | dzdo -S systemctl enable --now nessusagent
        {% else %}
        echo {{ ansible_become_password | quote }} | sudo -S systemctl enable --now nessusagent
        {% endif %}

    - name: Link Nessus Agent
      shell: |
        {% if ansible_become_method == 'dzdo' %}
        echo {{ ansible_become_password | quote }} | dzdo -S /opt/nessus_agent/sbin/nessuscli agent link --key={{ activation_key }} {% if mode != 'cloud' %} --manager-host={{ manager_host }} --manager-port={{ manager_port }} {% else %} --cloud {% endif %}
        {% else %}
        echo {{ ansible_become_password | quote }} | sudo -S /opt/nessus_agent/sbin/nessuscli agent link --key={{ activation_key }} {% if mode != 'cloud' %} --manager-host={{ manager_host }} --manager-port={{ manager_port }} {% else %} --cloud {% endif %}
        {% endif %}
      args:
        creates: "/opt/nessus_agent/.nessus/agent.key"
