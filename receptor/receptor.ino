#include <dummy.h>

// Receptor ESP32: recibe paquete [nonce|ct|tag] del emisor y verifica Ascon.
// Si el tag es valido, muestra la distancia. Ver README.md.

#include <Arduino.h>
#include <WiFi.h>

extern "C" {
#include "api.h"
}
extern "C" int crypto_aead_decrypt(
    unsigned char* m, unsigned long long* mlen,
    unsigned char* nsec, const unsigned char* c,
    unsigned long long clen, const unsigned char* ad,
    unsigned long long adlen, const unsigned char* npub,
    const unsigned char* k);

// --- Configuracion: completar antes de subir ---
const char* SSID     = "Felipe2";
const char* PASS     = "Felipe@Wifi";
const uint16_t PORT  = 3333;

// IP estatica del receptor en la red local. Fija aqui la direccion
// que el emisor usara en RECV_IP. Si cambias de red, actualiza estos valores.
IPAddress local_IP(10, 203, 129, 128);
IPAddress gateway(10, 203, 129, 23);
IPAddress subnet(255, 255, 255, 0);

// Misma clave de 16 bytes que el emisor.
static const uint8_t KEY[16] = {
  0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
  0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10
};

constexpr size_t NONCE_LEN = CRYPTO_NPUBBYTES;       // 16
constexpr size_t PT_LEN    = sizeof(float);          // 4
constexpr size_t CT_LEN    = PT_LEN + CRYPTO_ABYTES; // 20 (ct+tag)
constexpr size_t PKT_LEN   = NONCE_LEN + CT_LEN;     // 36

WiFiServer server(PORT);
uint8_t nonce[NONCE_LEN], plaintext[PT_LEN], recv_buf[PKT_LEN];

void setup() {
  Serial.begin(115200);
  WiFi.config(local_IP, gateway, subnet);
  WiFi.begin(SSID, PASS);
  while (WiFi.status() != WL_CONNECTED) delay(500);
  Serial.print("[wifi] IP="); Serial.println(WiFi.localIP());
  Serial.print("[wifi] GW="); Serial.println(WiFi.gatewayIP());
  server.begin();
}

void loop() {
  WiFiClient cli = server.available();
  if (!cli) return;
  if (cli.available() < (int)PKT_LEN) return;

  cli.readBytes(recv_buf, PKT_LEN);
  memcpy(nonce, recv_buf, NONCE_LEN);
  const uint8_t* ct = recv_buf + NONCE_LEN;

  Serial.print("[rx] pkt: ");
  for (size_t i = 0; i < PKT_LEN; i++) Serial.printf("%02X", recv_buf[i]);
  Serial.println();

  unsigned long long mlen = 0;
  int rc = crypto_aead_decrypt(plaintext, &mlen, nullptr,
                               ct, CT_LEN, nullptr, 0, nonce, KEY);

  if (rc == 0 && mlen == PT_LEN) {
    float cm;
    memcpy(&cm, plaintext, sizeof(float));
    Serial.printf("[rx] dist=%.2f cm (autenticado)\n", cm);
  } else {
    Serial.println("[rx] TAG INVALIDO -- paquete descartado");
  }
}