---
- name: Deploy Nessus Agent
  hosts: agents
  gather_facts: no
  vars:
    force_relink: true
    ansible_remote_tmp: /tmp

  pre_tasks:
    - name: Gather minimal OS facts
      setup:
        gather_subset:
          - '!all'
          - 'min'

  tasks:

    # ---------------- Remove Rapid7 ----------------
    - name: Upload Rapid7 remover
      copy:
        src: "r7remover.sh"
        dest: /tmp/r7remover.sh
        mode: "0755"

    - name: Run Rapid7 remover
      script: /tmp/r7remover.sh
      become: yes
      become_method: "{{ hostvars[inventory_hostname]['ansible_become_method'] }}"
      become_flags: "-S -tt"
      when: remove_rapid7 | bool

    # ---------------- Remove existing Nessus token ----------------
    - name: Remove existing Nessus token if force_relink
      shell: /opt/nessus_agent/sbin/nessuscli agent unlink
      become: yes
      become_method: "{{ hostvars[inventory_hostname]['ansible_become_method'] }}"
      become_flags: "-S -tt"
      ignore_errors: yes
      when: force_relink

    # ---------------- RHEL Packages ----------------
    - name: Upload RHEL 7 package
      copy:
        src: "el7.rpm"
        dest: "/tmp/el7.rpm"
        mode: '0755'
      when:
        - ansible_facts['distribution'] == "RedHat"
        - ansible_facts['distribution_major_version'] == "7"

    - name: Install RHEL 7 package
      shell: yum -y localinstall /tmp/el7.rpm
      become: yes
      become_method: "{{ hostvars[inventory_hostname]['ansible_become_method'] }}"
      become_flags: "-S -tt"
      when:
        - ansible_facts['distribution'] == "RedHat"
        - ansible_facts['distribution_major_version'] == "7"

    - name: Upload RHEL 8 package
      copy:
        src: "el8.rpm"
        dest: "/tmp/el8.rpm"
        mode: '0755'
      when:
        - ansible_facts['distribution'] == "RedHat"
        - ansible_facts['distribution_major_version'] == "8"

    - name: Install RHEL 8 package
      shell: dnf -y localinstall /tmp/el8.rpm
      become: yes
      become_method: "{{ hostvars[inventory_hostname]['ansible_become_method'] }}"
      become_flags: "-S -tt"
      when:
        - ansible_facts['distribution'] == "RedHat"
        - ansible_facts['distribution_major_version'] == "8"

    - name: Upload RHEL 9 package
      copy:
        src: "el9.rpm"
        dest: "/tmp/el9.rpm"
        mode: '0755'
      when:
        - ansible_facts['distribution'] == "RedHat"
        - ansible_facts['distribution_major_version'] == "9"

    - name: Install RHEL 9 package
      shell: dnf -y localinstall /tmp/el9.rpm
      become: yes
      become_method: "{{ hostvars[inventory_hostname]['ansible_become_method'] }}"
      become_flags: "-S -tt"
      when:
        - ansible_facts['distribution'] == "RedHat"
        - ansible_facts['distribution_major_version'] == "9"

    # ---------------- Debian/Ubuntu Packages ----------------
    - name: Upload Debian/Ubuntu package
      copy:
        src: "NessusAgent-10.9.0-ubuntu1604_amd64.deb"
        dest: "/tmp/NessusAgent-10.9.0-ubuntu1604_amd64.deb"
        mode: '0755'
      when: ansible_facts['distribution'] in ['Ubuntu', 'Debian']

    - name: Install Debian/Ubuntu package
      shell: apt-get install -y /tmp/NessusAgent-10.9.0-ubuntu1604_amd64.deb
      become: yes
      become_method: "{{ hostvars[inventory_hostname]['ansible_become_method'] }}"
      become_flags: "-S -tt"
      when: ansible_facts['distribution'] in ['Ubuntu', 'Debian']

    # ---------------- Start & Enable Nessus Agent ----------------
    - name: Enable and start Nessus Agent
      systemd:
        name: nessusagent
        state: started
        enabled: yes
      become: yes
      become_method: "{{ hostvars[inventory_hostname]['ansible_become_method'] }}"
      become_flags: "-S -tt"

    - name: Link Nessus Agent
      shell: >
        /opt/nessus_agent/sbin/nessuscli agent link
        --key={{ activation_key }}
        {% if mode == "cloud" %} --cloud {% else %} --manager-host={{ manager_host }} --manager-port={{ manager_port }} {% endif %}
      args:
        creates: "/opt/nessus_agent/.nessus/agent.key"
      become: yes
      become_method: "{{ hostvars[inventory_hostname]['ansible_become_method'] }}"
      become_flags: "-S -tt"
