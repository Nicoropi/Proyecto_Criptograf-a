# Sensor cifrado con Ascon-128 AEAD sobre ESP32

Emisor WiFi que mide distancia con un HY-SRF05 y la envia cifrada y autenticada a un receptor, usando el esquema estandarizado por NIST.

---

## 1. Que hace?

Un ESP32 lee la distancia de un sensor ultrasonico HY-SRF05, la cifra con Ascon-128 AEAD (clave de 16 bytes, nonce de 16 bytes, tag de 16 bytes) y la envia por WiFi (TCP) a otro ESP32 que verifica el tag antes de aceptar la lectura.

---

## 2. Ascon en 30 segundos

Ascon-128 es un cifrado autenticado (AEAD = Authenticated Encryption with Associated Data). En una sola operacion produce tres salidas: **texto cifrado**, **nonce publico** y **tag** de autenticacion.

| Parametro     | Tamano |
|---------------|--------|
| Clave (key)   | 16 B   |
| Nonce         | 16 B   |
| Tag           | 16 B   |
| Bloque (rate) | 16 B   |

El emisor calcula `tag = MAC(clave, nonce, "header" || cifrado)`. El receptor recalcula el tag sobre los bytes recibidos y los compara: si difieren en un solo bit, descarta el paquete. Ascon fue elegido ganador del concurso NIST Lightweight Cryptography (2023) y es el estandar para cifrado ligero en dispositivos restringidos.

Idea clave para la presentacion: **una sola operacion hace cifrado + autenticacion**. No hay modo "solo cifrar" ni "solo autenticar" que valga la pena considerar en AEAD.

---

## 3. Arquitectura del sistema

```
            WiFi (TCP, puerto 3333)
   ESP32 EMISOR  ─────────────────────►  ESP32 RECEPTOR
   HY-SRF05                              muestra distancia
   + Ascon-128 AEAD                      solo si tag OK
   [clave compartida 16B]
```

Ambos ESP32 comparten la misma clave de 16 bytes. Cualquier cambio de clave debe hacerse en los dos a la vez.

### Flujo del receptor

```
   WiFi TCP <- paquete 36B
        |
        v
   separar [nonce 16B | ciphertext+tag 20B]
        |
        v
   Ascon-128 AEAD.decrypt(key, nonce, ciphertext)
        |
        v
   tag valido?  --no--> descartar + log "TAG INVALIDO"
        |
       si
        v
   memcpy 4B -> float -> Serial.printf distancia
```

La verificacion del tag es **constante en tiempo** (no aborta temprano al detectar el primer byte malo), asi un atacante no puede medir tiempos para adivinar contenido.

---

## 4. Flujo del emisor

```
   HY-SRF05
      │
      ▼
   leer distancia (float, cm)
      │
      ▼
   serializar 4 bytes (memcpy, little-endian IEEE-754)
      │
      ▼
   construir nonce = [prefijo 12B | contador 4B LE]
      │
      ▼
   Ascon-128 AEAD.encrypt(key, nonce, plaintext)
      │
      ▼
   paquete = [nonce 16B || ciphertext 4B || tag 16B]
      │
      ▼
   WiFi TCP -> 192.168.0.50:3333
      │
      ▼
   persistir contador++ en NVS
```

---

## 5. Estructura del paquete

```
   offset:   0            16            32          36
             ├─────────────┼─────────────┼─────────────┤
             │   NONCE     │ CIPHERTEXT  │    TAG      │
             │   (16 B)    │   (N B)     │   (16 B)    │
             ├─────────────┼─────────────┼─────────────┤
   tamano:        16             N            16
```

- **Nonce (16 B):** se envia en claro. Es publico por diseno: cualquier atacante puede verlo sin comprometer la seguridad, siempre que **no se reuse nunca** con la misma clave.
- **Ciphertext (N B):** mismo tamano que el plaintext (4 B en este proyecto, distancia).
- **Tag (16 B):** el receptor recalcula MAC(clave, nonce, header||ciphertext) y compara con este tag. Si difiere -> paquete descartado.

Tamano total para nuestro caso (4 B de distancia): **16 + 4 + 16 = 36 bytes por paquete**.

---

## 6. Por que el nonce es unico?

En AEAD, **reusar un nonce con la misma clave es catastrofico**:

1. Si dos ciphertexts usan el mismo `(clave, nonce)`, un atacante puede calcular `m1 XOR m2` directamente, sin necesidad de la clave.
2. Tambien puede forjar nuevos ciphertexts con tag valido para ese nonce.

Por eso nuestro nonce tiene dos partes:

```
   [ prefijo fijo 12 B ][ contador 4 B little-endian ]
```

- El prefijo identifica al emisor (`"ASCON-EMIT-1"`).
- El contador es monotono, se incrementa en cada envio exitoso y se guarda en **NVS** (memoria flash) para sobrevivir a reinicios. Asi, aunque el ESP32 se resetee, no vuelve a enviar un nonce ya usado.

Capacidad maxima: 2^32 ~= 4.29 mil millones de paquetes. Suficiente para cualquier sensor realista.

---

## 7. Pines

### Emisor (HY-SRF05)

| Pin   | GPIO | Direccion | Notas                          |
|-------|------|-----------|--------------------------------|
| VCC   | 5V   | entrada   | alimentacion del sensor         |
| GND   | GND  | -         | masa comun                     |
| TRIG  | 5    | salida    | pulso de 10 us para disparar   |
| ECHO  | 18   | entrada   | pulso cuyo ancho = distancia   |

Modo de dos pines separados (TRIG y ECHO), mas confiable que el modo "single-wire".

### Receptor

Solo necesita la ESP32 basica. No hay sensor. Toda la comunicacion es por WiFi.

---

## 8. Como compilar y cargar

Tienes dos sketches: `emisor/` y `receptor/`. Cada uno debe ir en una carpeta con su mismo nombre (Arduino IDE lo exige).

### Opcion A: Arduino IDE

Para **cada** sketch (emisor y receptor):

1. Abrir el `.ino` correspondiente en Arduino IDE (con el core ESP32 ya instalado).
2. Copiar los archivos de Ascon a la **misma carpeta** del sketch desde `ASCON_algorithm/crypto_aead/asconaead128/esp32/`:
   ```
   api.h, ascon.h, constants.h, core.c, core.h,
   permutations.c, permutations.h, lendian.h,
   printstate.c, printstate.h
   ```
   Mas `encrypt.c` para el **emisor**, o `decrypt.c` para el **receptor** (no ambos en el mismo sketch, solo el que uses).
3. Editar y completar `SSID`, `PASS`, `RECV_IP`/`PORT`, y verificar que `KEY[16]` sea **identica** en ambos `.ino`.
4. Seleccionar placa "ESP32 Dev Module", puerto correcto, **subir**.

### Opcion B: PlatformIO

Dos environments en el mismo `platformio.ini`, uno por sketch. Los `.c/.h` de Ascon van en `src/` de cada environment.

---

## 9. Como probarlo

1. Conectar el HY-SRF05 a los pines indicados (5V, GND, GPIO5, GPIO18).
2. Abrir **Serial Monitor** a 115200 baud (ambos, en ventanas separadas).
3. Verificar en la consola del **emisor**:

```
=== ASCON-128 AEAD EMISOR ESP32 ===
[nvs] nonce_ctr cargado = 0
[wifi] IP=10.203.129.88
[tx] dist=42.31 cm  ctr=0  sent=ok
[tx] pkt: 4153434F4E2D454D49542D31 0000002A A3F2E1B7... 7B9C4D2E...
[tx] dist=42.28 cm  ctr=1  sent=ok
[tx] pkt: 4153434F4E2D454D49542D31 0000002B 5C9A0E81... D4F12B7C...
...
```

Y en el **receptor**:

```
[wifi] IP=10.203.129.128
[rx] pkt: 4153434F4E2D454D49542D31 0000002A A3F2E1B7... 7B9C4D2E...
[rx] dist=42.31 cm (autenticado)
[rx] pkt: 4153434F4E2D454D49542D31 0000002B 5C9A0E81... D4F12B7C...
[rx] dist=42.28 cm (autenticado)
```

### Como leer la linea `[tx] pkt:` o `[rx] pkt:`

Los 36 bytes se imprimen en hexadecimal. La linea se divide asi:

```
[tx] pkt: 4153434F4E2D454D49542D31 0000002A A3F2E1B7C04D... 7B9C4D2E81F0...
         ├── nonce (16B) ─────────┤├──ctr─┤├ ciphertext (4B) ─┤├── tag (16B) ──┤
         └─ "ASCON-EMIT-1" en      └─ LE   └─ random            └─ random
            ASCII legible
```

| Tramo | Bytes | Contenido | Como se ve |
|-------|-------|-----------|------------|
| nonce | 16 | prefijo fijo + contador LE | primeros 12B son ASCII `ASCON-EMIT-1`, ultimos 4B son el contador en little-endian |
| ciphertext | 4 | distancia float cifrada | **indistinguible de random** |
| tag | 16 | MAC sobre nonce+ciphertext | **indistinguible de random** |

**Demostracion didactica:** los unicos bytes que tienen estructura visible son los 12B del prefijo del nonce. Todo lo demas es ruido criptografico. Si dos paquetes tienen la misma distancia y distinto contador, **los ciphertext y los tags son completamente distintos** (esto es la no-determinismo del nonce en accion).

4. Acercar la mano al sensor: la distancia debe bajar. El `ctr` debe incrementarse. Si `sent=fail`, revisar IP/puerto del receptor o que este escuchando TCP.

5. Probar la **autenticacion**: si se modifica un solo byte del paquete en transito (usando un man-in-the-middle didactico), el receptor debe descartar el paquete porque el tag no coincide.

> **Nota academica:** imprimir el paquete completo en el Serial es util para visualizar la salida de Ascon, pero en produccion se eliminaria. Un atacante con acceso al Serial del emisor podria capturar paquetes y retransmitirlos (replay). En este proyecto la mitigacion academica es el contador de nonce en NVS: el receptor, en una version mas robusta, rechazaria nonces ya vistos.

---

## 10. Receptor (`receptor/receptor.ino`)

- Configura una **IP estatica** (`10.203.129.128`) con `WiFi.config(...)`, independiente del DHCP del router. Asi, tras cualquier reinicio, el receptor siempre esta en la misma direccion.
- Abre un `WiFiServer` en el puerto TCP 3333.
- Por cada conexion: lee 36 bytes, los imprime en hex, separa `nonce` y `ciphertext+tag`, llama `crypto_aead_decrypt`.
- Si la funcion retorna 0 (tag OK), muestra la distancia por Serial.
- Si retorna -1 (tag invalido), descarta el paquete y loguea `TAG INVALIDO`.

El emisor apunta a esa misma IP fija (`RECV_IP = "10.203.129.128"` en este despliegue). Si cambias de red, actualizar tanto `local_IP`/`gateway` en el receptor como `RECV_IP` en el emisor.

> **Nota de despliegue:** este proyecto se probo con un celular Android como AP (rango `10.203.129.x`, gateway `10.203.129.23`). El emisor obtiene su IP por DHCP; el receptor usa IP estatica fija. Si la red cambia, hay que actualizar `local_IP` y `RECV_IP`.

Comportamiento esperado en consola del receptor:
```
[rx] dist=42.31 cm (autenticado)
[rx] dist=42.28 cm (autenticado)
[rx] TAG INVALIDO -- paquete descartado
```

Para probar la autenticacion: con un man-in-the-middle didactico (incluso un proxy Python entre emisor y receptor) modifica **un solo byte** del ciphertext o del tag. El receptor debe descartar inmediatamente.

---

## 11. Limitaciones conocidas

- **Clave hardcodeada en firmware.** Cualquiera con acceso fisico al ESP32 puede leerla con `esptool.py read_flash`. Para produccion: almacenar en eFuse o en un ATECC608A.
- **Un solo receptor.** La `RECEIVER_IP` esta fija en el codigo. Cambiar receptor requiere re-flashear.
- **No hay proteccion contra replay** mas alla del contador de nonce. Un atacante que graba un paquete y lo retransmite mas tarde sera rechazado (porque el nonce ya se uso), pero un protocolo completo deberia sumar timestamp + nonce del receptor.
- **WiFi en claro.** El canal TCP no es TLS. Ascon protege el contenido del paquete, no el canal. Es academico: en produccion se anidaria TLS encima de Ascon o se usaria solo Ascon segun el caso.
- **Contador en NVS se resetea** si la NVS se corrompe (muy raro, ~cada 100k escrituras por sector). El emisor detectaria el contador `< ctr anterior` y abortaria para no reusar nonces.

---

**Proyecto Final — Criptografia y Ciberseguridad, 7mo Semestre.**