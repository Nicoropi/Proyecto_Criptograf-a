// Emisor ESP32: HY-SRF05 + Ascon-128 AEAD sobre WiFi (TCP)
// Lee distancia, cifra con Ascon, manda paquete [nonce|ct|tag] al receptor.
// Ver README.md para la explicacion completa.

#include <Arduino.h>
#include <WiFi.h>
#include <Preferences.h>

extern "C" {
#include "api.h"
}
extern "C" int crypto_aead_encrypt(
    unsigned char* c, unsigned long long* clen,
    const unsigned char* m, unsigned long long mlen,
    const unsigned char* ad, unsigned long long adlen,
    const unsigned char* nsec, const unsigned char* npub,
    const unsigned char* k);

// --- Configuracion: completar antes de subir ---
const char* SSID       = "Felipe2";
const char* PASS       = "Felipe@Wifi";
// IP del receptor. Debe coincidir con la IP estatica configurada en receptor.ino.
const char* RECV_IP    = "10.203.129.128";
const uint16_t RECV_PORT = 3333;

// Clave de 16 bytes, IDENTICA en el receptor.
static const uint8_t KEY[16] = {
  0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
  0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10
};

// Nonce = 12B prefijo fijo + 4B contador (LE). Contador vive en NVS.
static const uint8_t NONCE_PRE[12] = {'A','S','C','O','N','-','E','M','I','T','-','1'};

constexpr uint8_t  TRIG = 5, ECHO = 18;
constexpr uint16_t PERIODO_MS = 500;
constexpr size_t   PT_LEN = sizeof(float);    // 4 bytes
constexpr size_t   CT_LEN = PT_LEN + CRYPTO_ABYTES; // 4 + 16 = 20
constexpr size_t   PKT_LEN = CRYPTO_NPUBBYTES + CT_LEN; // 16 + 20 = 36

Preferences prefs;
WiFiClient   tcp;
uint32_t     nonce_ctr = 0;
uint8_t      packet[PKT_LEN], nonce[CRYPTO_NPUBBYTES];
uint8_t      plaintext[PT_LEN], ciphertext[CT_LEN];

float leer_cm() {
  digitalWrite(TRIG, LOW);  delayMicroseconds(2);
  digitalWrite(TRIG, HIGH); delayMicroseconds(10);
  digitalWrite(TRIG, LOW);
  unsigned long us = pulseIn(ECHO, HIGH, 25000UL);
  return (us == 0) ? -1.0f : (float)us / 58.0f;
}

void armar_nonce() {
  memcpy(nonce, NONCE_PRE, 12);
  nonce[12] = nonce_ctr        & 0xFF;
  nonce[13] = (nonce_ctr >>  8) & 0xFF;
  nonce[14] = (nonce_ctr >> 16) & 0xFF;
  nonce[15] = (nonce_ctr >> 24) & 0xFF;
}

bool enviar(const uint8_t* buf, size_t n) {
  if (WiFi.status() != WL_CONNECTED) return false;
  if (!tcp.connected() && !tcp.connect(RECV_IP, RECV_PORT)) return false;
  return tcp.write(buf, n) == n;
}

void setup() {
  Serial.begin(115200);
  pinMode(TRIG, OUTPUT);
  pinMode(ECHO, INPUT);
  prefs.begin("ascon", false);
  nonce_ctr = prefs.getUInt("ctr", 0);
  WiFi.begin(SSID, PASS);
  while (WiFi.status() != WL_CONNECTED) delay(500);
  Serial.print("[wifi] IP="); Serial.println(WiFi.localIP());
}

void loop() {
  float cm = leer_cm();
  armar_nonce();

  if (cm >= 0.0f) memcpy(plaintext, &cm, sizeof(float));

  unsigned long long clen = 0;
  crypto_aead_encrypt(ciphertext, &clen,
                      plaintext, PT_LEN,
                      nullptr, 0, nullptr, nonce, KEY);

  memcpy(packet, nonce, CRYPTO_NPUBBYTES);
  memcpy(packet + CRYPTO_NPUBBYTES, ciphertext, CT_LEN);

  bool ok = enviar(packet, PKT_LEN);
  if (ok) {
    nonce_ctr++;
    prefs.putUInt("ctr", nonce_ctr);
  }

  Serial.printf("[tx] dist=%.2fcm ctr=%lu sent=%s\n",
                cm, (unsigned long)nonce_ctr, ok ? "ok" : "fail");
  Serial.print("[tx] pkt: ");
  for (size_t i = 0; i < PKT_LEN; i++) Serial.printf("%02X", packet[i]);
  Serial.println();
  delay(PERIODO_MS);
}