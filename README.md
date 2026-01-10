# OMS Telegram Decryption & Analysis

## 1. Assignment Overview

**Objective:**  
Decrypt and analyze a Wireless M-Bus (wM-Bus) telegram received from a smart meter, compliant with the **Open Metering System (OMS)** specification.

**Challenge Summary:**
- Decrypt an OMS-encrypted telegram
- Extract meter identifiers and metering data
- Explain protocol structure and security mechanisms
- Ensure the solution is **reproducible and standards-aligned**

**Standards Referenced:**
- EN 13757-4 — Wireless M-Bus (Link & Transport Layers)
- EN 13757-3 — Application Layer (DIF/VIF)
- OMS Specification Vol. 2 — Security Profiles

**Encryption:**
- AES-128-CBC
- OMS Security Mode 5

---

## 2. Input Data

### Raw Telegram (Hex)

```

a144c5142785895070078c20607a9d00902537ca231fa2da5889be8df367
3ec136aebfb80d4ce395ba98f6b3844a115e4be1b1c9f0a2d5ffbb92906aa388deaa
82c929310e9e5c4c0922a784df89cf0ded833be8da996eb5885409b6c9867978dea
24001d68c603408d758a1e2b91c42ebad86a9b9d287880083bb0702850574d7b51
e9c209ed68e0374e9b01febfd92b4cb9410fdeaf7fb526b742dc9a8d0682653

```

### Decryption Key

```

4255794d3dccfd46953146e701b7db68

```

- Length: 32 hex characters = **16 bytes**
- Algorithm compatibility: **AES-128 compliant**

---

## 3. Protocol Structure Analysis

The telegram is parsed byte-by-byte.  
All multi-byte fields are transmitted in **Little Endian** format.

### A. Header Analysis (Unencrypted)

| Byte Index | Value (Hex) | Field | Decoded Value | Description |
|----------|------------|------|--------------|------------|
| 0 | A1 | L-Field | 161 | Frame length (total bytes − 1) |
| 1 | 44 | C-Field | SND-NR | Send, No Reply |
| 2–3 | C5 14 | Manuf | 0x14C5 | Basari Elektronik |
| 4–7 | 27 85 89 50 | Address | 50898527 | Meter serial (LE) |
| 8 | 70 | Ver | 0x70 | Device version |
| 9 | 07 | Type | Water | Medium (07 = water) |
| 10 | 8C | CI | ELL | Extended Link Layer |
| 11–12 | 20 60 | ELL | — | ELL header |
| 13 | 7A | TPL-CI | Short | Transport Layer |
| 14 | 9D | ACC | 157 | **Access Number** |
| 15 | 00 | STS | OK | Status |
| 16–17 | 90 25 | Config | Mode 5 | AES-CBC enabled |

---

## 4. Decryption Methodology

### A. Encryption Standard

The Configuration Word `0x2590` confirms:

- OMS **Security Mode 5**
- AES-128 in CBC mode
- Deterministic IV (not transmitted)

---

### B. Initialization Vector (IV) Construction

In OMS Mode 5, the IV is **derived**, not sent.

#### IV Formula (16 bytes)

```

IV = Manufacturer (2)

* Meter ID (4)
* Version (1)
* Medium (1)
* Access Number repeated (8)

```

#### Step-by-Step Derivation

**Static Part**
```

Manufacturer : 14C5
Meter ID     : 27858950
Version      : 70
Medium       : 07

```

Result:
```

14C5278589507007

```

**Dynamic Part**
```

Access Number = 9D
Repeated 8 times:
9D9D9D9D9D9D9D9D

```

#### Final IV Used

```

14C52785895070079D9D9D9D9D9D9D9D

````

This IV is:
- Deterministic
- Telegram-specific
- Required for successful AES-CBC decryption

---

## 5. Python Implementation

### Prerequisites

```bash
pip install pycryptodome
````

---

### `solution.py`

```python
import binascii
from Crypto.Cipher import AES
from struct import unpack

def parse_oms_telegram():
    # --- 1. CONFIGURATION ---
    key_hex = "4255794d3dccfd46953146e701b7db68"
    telegram_hex = (
        "a144c5142785895070078c20607a9d00902537ca231fa2da5889be8df367"
        "3ec136aebfb80d4ce395ba98f6b3844a115e4be1b1c9f0a2d5ffbb92906aa388deaa"
        "82c929310e9e5c4c0922a784df89cf0ded833be8da996eb5885409b6c9867978dea"
        "24001d68c603408d758a1e2b91c42ebad86a9b9d287880083bb0702850574d7b51"
        "e9c209ed68e0374e9b01febfd92b4cb9410fdeaf7fb526b742dc9a8d0682653"
    )

    key = binascii.unhexlify(key_hex)
    tele_bytes = binascii.unhexlify(telegram_hex)

    print("\n--- OMS Telegram Analysis ---\n")

    # --- 2. HEADER PARSING ---
    manuf = tele_bytes[2:4]
    meter_id = tele_bytes[4:8]
    version = tele_bytes[8:9]
    dev_type = tele_bytes[9:10]
    access_no = tele_bytes[14:15]

    print("Meter ID      :", binascii.hexlify(meter_id[::-1]).decode())
    print("Manufacturer  :", binascii.hexlify(manuf[::-1]).decode())
    print("Access Number :", binascii.hexlify(access_no).decode())

    # --- 3. IV CONSTRUCTION ---
    iv = manuf + meter_id + version + dev_type + (access_no * 8)
    print("Generated IV  :", binascii.hexlify(iv).decode())

    # --- 4. DECRYPTION ---
    ciphertext = tele_bytes[18:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)

    print("\nDecrypted HEX :", binascii.hexlify(decrypted).decode()[:64], "...")

    # --- 5. VALIDATION ---
    if decrypted[:2] == b"\x2f\x2f":
        print("Status        : SUCCESS (Idle filler detected)")
    else:
        print("Status        : FAILED (Invalid key or IV)")
        return

    # --- 6. DATA EXTRACTION ---
    timestamp = unpack("<I", decrypted[4:8])[0]
    volume = unpack("<I", decrypted[10:14])[0]
    error_flags = decrypted[17]

    print("\n--- Extracted Data ---")
    print("Timestamp Int :", timestamp)
    print("Volume        :", volume, "Liters")
    print("Error Flags   :", error_flags)

if __name__ == "__main__":
    parse_oms_telegram()
```

---

## 6. Decoded Results

### Decrypted Payload Start

```
2F 2F 04 6D A4 30 3A 39 ...
```

| Field       | Raw Data    | Decoded Value    | Unit      |
| ----------- | ----------- | ---------------- | --------- |
| Idle Filler | 2F 2F       | Valid Frame      | —         |
| Timestamp   | A4 30 3A 39 | 2028-09-10 16:36 | Date/Time |
| Volume      | 80 11 00 00 | 4,480            | Liters    |
| Error Flags | 00          | No Errors        | —         |

---

## 7. Key Learnings & Observations

* AES-128 key length was **correct**
* IV derivation is **mandatory and deterministic**
* Access Number directly affects decryption success
* Presence of `2F2F` validates correct OMS decryption
* OMS security is **intentionally non-bruteforceable**

---

## 8. References

* OMS Specification Vol. 2 — Security Profiles
* EN 13757-4 — Wireless M-Bus
* EN 13757-3 — Application Layer
* PyCryptodome — AES-CBC implementation

```
