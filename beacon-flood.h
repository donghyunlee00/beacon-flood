#include <cstdint>
#include <stdint.h>
#include "mac.h"

#define NON 0x00

#pragma pack(push, 1)
struct RadiotapHdr
{
    uint8_t revision;
    uint8_t pad;
    uint16_t length;
    uint32_t present_flags;
};

struct BeaconFrame
{
    uint16_t frame_control;
    uint16_t duration;
    Mac dmac;
    Mac smac;
    Mac bss_id;
    uint16_t sequence;
};

struct WirelessManagement
{
    uint64_t timestamp;
    uint16_t interval;
    uint16_t capabilities;
    uint8_t tag_number;
    uint8_t tag_length;
    unsigned char ssid[40];
};

struct BeaconPkt
{
    RadiotapHdr radiotaphdr;
    BeaconFrame beaconframe;
    WirelessManagement wirelessmanagement;
};
#pragma pack(pop)
