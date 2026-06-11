#include "hb_headers.h"

#include <stdio.h>      
#include <string.h>     
#include <ctype.h>      
#include <arpa/inet.h>  


// ------------------------------------------------------------
// Internal helper: collect only hex digits from MAC string
// Example:
// "90:de:80:09:9a:56" -> "90de80099a56"
// ------------------------------------------------------------
static bool collect_mac_hex(const char* src, char hex[13]) {
    int j = 0;

    if (src == NULL) {
        return false;
    }

    for (int i = 0; src[i] != '\0'; i++) {
        if (isxdigit((unsigned char)src[i])) {
            if (j >= 12) {
                return false;
            }
            hex[j++] = src[i];
        }
    }

    if (j != 12) {
        return false;
    }

    hex[12] = '\0';
    return true;
}



// ------------------------------------------------------------
// Internal helper: parse validated 12-digit MAC hex string
// Example input: "90de80099a56"
// ------------------------------------------------------------
static bool parse_mac_hex_string(const char* hex, hb_mac* out) {
    if (hex == NULL || out == NULL) {
        return false;
    }

    memset(out->bytes, 0, MAC_ADDR_LEN);

    int res = sscanf(hex,
                     "%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx",
                     &out->bytes[0], &out->bytes[1], &out->bytes[2],
                     &out->bytes[3], &out->bytes[4], &out->bytes[5]);

    return (res == MAC_ADDR_LEN);
}


// ------------------------------------------------------------
// Internal helper: full MAC string parser
// - handles delimiter removal
// - validates length/content
// - converts to hb_mac
// ------------------------------------------------------------
static bool parse_mac_string(const char* src, hb_mac* out) {
    char hex[13];

    if (out == NULL) {
        return false;
    }

    memset(out->bytes, 0, MAC_ADDR_LEN);

    if (!collect_mac_hex(src, hex)) {
        return false;
    }

    return parse_mac_hex_string(hex, out);
}


// ------------------------------------------------------------
// Internal helper: parse IPv4 string into 4 octets
// - rejects out-of-range numbers
// - rejects trailing garbage
// Example input: "172.20.10.6"
// ------------------------------------------------------------
static bool parse_ip_parts(const char* src, uint8_t part[4]) {
    unsigned int temp[4];
    char tail;

    if (src == NULL || part == NULL) {
        return false;
    }

    int res = sscanf(src, "%u.%u.%u.%u%c",
                     &temp[0], &temp[1], &temp[2], &temp[3], &tail);

    if (res != 4) {
        return false;
    }

    for (int i = 0; i < 4; i++) {
        if (temp[i] > 255) {
            return false;
        }
        part[i] = (uint8_t)temp[i];
    }

    return true;
}


// ------------------------------------------------------------
// Internal helper: full IP string parser
// - parses dotted IPv4 string
// - returns host byte order uint32_t
// ------------------------------------------------------------
static bool parse_ip_string(const char* src, uint32_t* out) {
    uint8_t part[4];
    uint32_t ip = 0;

    if (out == NULL) {
        return false;
    }

    *out = 0;

    if (!parse_ip_parts(src, part)) {
        return false;
    }

    memcpy(&ip, part, 4);
    ip = ntohl(ip);

    *out = ip;
    return true;
}


// ------------------------------------------------------------
// Validation functions
// ------------------------------------------------------------
bool Mac_is_valid_string(const char* s) {
    hb_mac dummy;
    return parse_mac_string(s, &dummy);
}


bool Ip_is_valid_string(const char* s) {
    uint32_t dummy;
    return parse_ip_string(s, &dummy);
}


// ------------------------------------------------------------
// Parse functions
// ------------------------------------------------------------
hb_mac Mac_parse(const char* s) {
    hb_mac mac = {0};
    parse_mac_string(s, &mac);
    return mac;
}


uint32_t Ip_parse(const char* s) {
    uint32_t ip = 0;
    parse_ip_string(s, &ip);
    return ip;
}


// ------------------------------------------------------------
// Special MAC values
// ------------------------------------------------------------
hb_mac Mac_null(void) {
    hb_mac mac = { .bytes = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00} };
    return mac;
}


hb_mac Mac_broadcast(void) {
    hb_mac mac = { .bytes = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF} };
    return mac;
}


// ------------------------------------------------------------
// MAC tests
// ------------------------------------------------------------
bool Mac_is_null(hb_mac mac) {
    for (int i = 0; i < MAC_ADDR_LEN; i++) {
        if (mac.bytes[i] != 0x00) {
            return false;
        }
    }
    return true;
}


bool Mac_is_broadcast(hb_mac mac) {
    for (int i = 0; i < MAC_ADDR_LEN; i++) {
        if (mac.bytes[i] != 0xFF) {
            return false;
        }
    }
    return true;
}
