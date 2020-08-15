#include "stdlib.h"
#include "pcapplusplus/PcapFileDevice.h"

int main(int argc, char* argv[])
{
    pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader("maccdc2012_00000.pcap");

    if (reader == NULL)
    {
        printf("Cannot determine reader for file type\n");
        exit(1);
    }

    if (!reader->open())
    {
        printf("Cannot open input.pcap for reading\n");
        exit(1);
    }

    // create the stats object
    pcap_stat stats;

    // read stats from reader and print them
    reader->getStatistics(stats);
    printf("Read %d packets successfully and %d packets could not be read\n", stats.ps_recv, stats.ps_drop);

    reader->close();

    return 0;
}