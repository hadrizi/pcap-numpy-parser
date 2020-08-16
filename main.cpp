#if !defined(WIN32) && !defined(WINx64)
#include "in.h" // this is for using ntohs() and htons() on non-Windows OS's
#endif

#define NPY_NO_DEPRECATED_API NPY_1_7_API_VERSION
#define SIZE 30
#define FEATURES_AMOUNT 40

#include <stdio.h>
#include <stdlib.h>

#include <string>
#include <iostream>
#include <iomanip>
#include <experimental/filesystem>

#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "HttpLayer.h"
#include "PcapFileDevice.h"

#include <Python.h>
#include <numpy/arrayobject.h>

namespace fs = std::experimental::filesystem;
namespace{
    long double getProtocolTypeAsLDouble(pcpp::ProtocolType protocolType)
    {
        switch (protocolType)
        {
        case pcpp::Ethernet:
            return 1.0f;
        case pcpp::IPv4:
            return 2.0f;
        case pcpp::IPv6:
            return 3.0f;
        case pcpp::IP:
            return 4.0f;
        case pcpp::TCP:
            return 5.0f;        
        case pcpp::UDP:
            return 6.0f;
        case pcpp::HTTPRequest:
        case pcpp::HTTPResponse:
        case pcpp::HTTP:
            return 7.0f;
        case pcpp::ARP:
            return 8.0f;
        case pcpp::VLAN:
            return 9.0f;
        case pcpp::ICMP:
            return 10.0f;
        case pcpp::PPPoESession:
        case pcpp::PPPoEDiscovery:
        case pcpp::PPPoE:
            return 11.0f;
        case pcpp::DNS:
            return 12.0f;
        case pcpp::GREv0:
        case pcpp::GREv1:
        case pcpp::GRE:
            return 13.0f;
        case pcpp::PPP_PPTP:
            return 14.0f;
        case pcpp::SSL:
            return 15.0f;  
        case pcpp::SLL:
            return 16.0f;
        case pcpp::DHCP:
            return 17.0f;
        case pcpp::NULL_LOOPBACK:
            return 18.0f;
        case pcpp::IGMP:
        case pcpp::IGMPv1:
        case pcpp::IGMPv2:
        case pcpp::IGMPv3:
            return 19.0f;
        case pcpp::GenericPayload:
            return 20.0f;
        case pcpp::VXLAN:
            return 21.0f;
        case pcpp::SIPRequest:
        case pcpp::SIPResponse:
        case pcpp::SIP:
            return 22.0f;
        case pcpp::SDP:
            return 23.0f;
        case pcpp::PacketTrailer:
            return 24.0f; 
        default:
            return .0f;
        }
    }

    std::string printTcpFlags(pcpp::TcpLayer* tcpLayer)
    {
        std::string result = "";
        if (tcpLayer->getTcpHeader()->synFlag == 1)
            result += "SYN ";
        if (tcpLayer->getTcpHeader()->ackFlag == 1)
            result += "ACK ";
        if (tcpLayer->getTcpHeader()->pshFlag == 1)
            result += "PSH ";
        if (tcpLayer->getTcpHeader()->cwrFlag == 1)
            result += "CWR ";
        if (tcpLayer->getTcpHeader()->urgFlag == 1)
            result += "URG ";
        if (tcpLayer->getTcpHeader()->eceFlag == 1)
            result += "ECE ";
        if (tcpLayer->getTcpHeader()->rstFlag == 1)
            result += "RST ";
        if (tcpLayer->getTcpHeader()->finFlag == 1)
            result += "FIN ";

        return result;
    }

    std::string printTcpOptionType(pcpp::TcpOptionType optionType)
    {
        switch (optionType)
        {
        case pcpp::PCPP_TCPOPT_NOP:
            return "NOP";
        case pcpp::PCPP_TCPOPT_TIMESTAMP:
            return "Timestamp";
        default:
            return "Other";
        }
    }

    std::string printHttpMethod(pcpp::HttpRequestLayer::HttpMethod httpMethod)
    {
        switch (httpMethod)
        {
        case pcpp::HttpRequestLayer::HttpGET:
            return "GET";
        case pcpp::HttpRequestLayer::HttpPOST:
            return "POST";
        default:
            return "Other";
        }
    }

    // NOT USED
    // use it as example of how to handle layers
    void getPcapData(char* filename)
    {
        // use the IFileReaderDevice interface to automatically identify file type (pcap/pcap-ng)
        // and create an interface instance that both readers implement
        pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader(filename);

        // verify that a reader interface was indeed created
        if (reader == NULL)
        {
            printf("Cannot determine reader for file type\n");
            exit(1);
        }

        // open the reader for reading
        if (!reader->open())
        {
            printf("Cannot open input.pcap for reading\n");
            exit(1);
        }

        // read the first (and only) packet from the file
        pcpp::RawPacket rawPacket;
        if (!reader->getNextPacket(rawPacket))
        {
            printf("Couldn't read the first packet in the file\n");
            exit(1);
        }

        // close the file reader, we don't need it anymore
        reader->close();

        // parse the raw packet into a parsed packet
        pcpp::Packet parsedPacket(&rawPacket);

        puts("\nETHERNET LAYER");

        // now let's get the Ethernet layer
        pcpp::EthLayer* ethernetLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
        if (ethernetLayer == NULL)
        {
            printf("Something went wrong, couldn't find Ethernet layer\n");
            exit(1);
        }

        // print the source and dest MAC addresses and the Ether type
        printf("Source MAC address: %s\n", ethernetLayer->getSourceMac().toString().c_str());
        printf("Destination MAC address: %s\n", ethernetLayer->getDestMac().toString().c_str());
        printf("Ether type = 0x%X\n", ntohs(ethernetLayer->getEthHeader()->etherType));

        puts("\nIPv4 LAYER");

        // let's get the IPv4 layer
        pcpp::IPv4Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
        if (ipLayer == NULL)
        {
            printf("Something went wrong, couldn't find IPv4 layer\n");
            exit(1);
        }

        // print source and dest IP addresses, IP ID and TTL
        printf("Source IP address: %s\n", ipLayer->getSrcIpAddress().toString().c_str());
        printf("Destination IP address: %s\n", ipLayer->getDstIpAddress().toString().c_str());
        printf("IP ID: 0x%X\n", ntohs(ipLayer->getIPv4Header()->ipId));
        printf("TTL: %d\n", ipLayer->getIPv4Header()->timeToLive);

        puts("\nTCP LAYER");

        // let's get the TCP layer
        pcpp::TcpLayer* tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
        if (tcpLayer == NULL)
        {
            printf("Something went wrong, couldn't find TCP layer\n");
            exit(1);
        }

        // printf TCP source and dest ports, window size, and the TCP flags that are set in this layer
        printf("Source TCP port: %d\n", (int)ntohs(tcpLayer->getTcpHeader()->portSrc));
        printf("Destination TCP port: %d\n", (int)ntohs(tcpLayer->getTcpHeader()->portDst));
        printf("Window size: %d\n", (int)ntohs(tcpLayer->getTcpHeader()->windowSize));
        printf("TCP flags: %s\n", printTcpFlags(tcpLayer).c_str());
        // go over all TCP options in this layer and print its type
        printf("TCP options: ");
        for (pcpp::TcpOption tcpOption = tcpLayer->getFirstTcpOption(); tcpOption.isNotNull(); tcpOption = tcpLayer->getNextTcpOption(tcpOption))
        {
            printf("%s ", printTcpOptionType(tcpOption.getTcpOptionType()).c_str());
        }
        printf("\n");
        
        puts("\nHTTP LAYER");

        // let's get the HTTP request layer
        pcpp::HttpRequestLayer* httpRequestLayer = parsedPacket.getLayerOfType<pcpp::HttpRequestLayer>();
        if (httpRequestLayer == NULL)
        {
            printf("Something went wrong, couldn't find HTTP request layer\n");
            exit(1);
        }

        // print HTTP method and URI. Both appear in the first line of the HTTP request
        printf("HTTP method: %s\n", printHttpMethod(httpRequestLayer->getFirstLine()->getMethod()).c_str());
        printf("HTTP URI: %s\n", httpRequestLayer->getFirstLine()->getUri().c_str());
        // print values of the following HTTP field: Host, User-Agent and Cookie
        printf("HTTP host: %s\n", httpRequestLayer->getFieldByName(PCPP_HTTP_HOST_FIELD)->getFieldValue().c_str());
        printf("HTTP user-agent: %s\n", httpRequestLayer->getFieldByName(PCPP_HTTP_USER_AGENT_FIELD)->getFieldValue().c_str());
        printf("HTTP cookie: %s\n", httpRequestLayer->getFieldByName(PCPP_HTTP_COOKIE_FIELD)->getFieldValue().c_str());
        // print the full URL of this request
        printf("HTTP full URL: %s\n", httpRequestLayer->getUrl().c_str());
    }

}
namespace{
    long double getFeature1(time_t s, time_t e)
    {
        return e-s;
    }

    long double getFeature2(pcpp::ProtocolType protocolType)
    {
        return getProtocolTypeAsLDouble(protocolType);
    }

    long double getFeature3(pcpp::ProtocolType protocolType)
    {
        return getProtocolTypeAsLDouble(protocolType);
    }

    long double getFeature4()
    {
        return 1.0f;
    }

    /*
    * src - connection initializer, originator (source)
    * dst -  connection responder (destination)
    *
    * 1. srcIP sent SYN
    * 2. dstIP sent RST
    */ 
    const long double inline is_rej_flag( std::vector<std::pair<pcpp::IPv4Address, pcpp::tcphdr*>> conn_dump){
        if(conn_dump.size()>0){
            if( conn_dump[0].second != NULL){
                const bool isDifferentIPs = conn_dump[1].first != conn_dump[0].first;
                const bool isSrcSynFlag = conn_dump[0].second->synFlag == 1;
                const bool isDstRstFlag = conn_dump[0].second->rstFlag == 1;
                return (isDifferentIPs && isSrcSynFlag && isDstRstFlag) ? 1.0f : 0.0f;
            }
        }
        return 0;
    }

}

//----------------------- Flag 4 status of connection Normal or Error (REJ)

/**
 * For more info about SYN,ACK,RST flags on TCP
 * https://stackoverflow.com/questions/1752219/rejecting-a-tcp-connection-before-its-being-accepted
 * http://www.takakura.com/Kyoto_data/BenchmarkData-Description-v5.pdf
 * 
*/



/**
 * Create a dataset string in correct format. 
 * Splitted .PCAP is a one connection
 * 
 */
void readPcapFile(std::string filename, long double features[], bool log = false)
{
    // use the IFileReaderDevice interface to automatically identify file type (pcap/pcap-ng)
    // and create an interface instance that both readers implement
    pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader(filename.c_str());

    // verify that a reader interface was indeed created
    if (reader == NULL)
    {
        printf("Cannot determine reader for file type\n");
        exit(1);
    }

    // open the reader for reading
    if (!reader->open())
    {
        printf("Cannot open input.pcap for reading\n");
        exit(1);
    }

    // read the first (and only) packet from the file
    pcpp::RawPacket rawPacket;
    if (!reader->getNextPacket(rawPacket))
    {
        printf("Couldn't read the first packet in the file\n");
        exit(1);
    }

    pcpp::Packet firstParsedPacket(&rawPacket);

    
    time_t start_conn = rawPacket.getPacketTimeStamp().tv_sec;

    long double sourceData = 0;
    long double destData = 0;
    pcpp::IPv4Address srcIP = firstParsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getSrcIpAddress(); // source IP  (connection initializer)
    pcpp::IPv4Address dstIP = firstParsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getDstIpAddress(); //destination IP (connection responder)

    pcpp::Layer* firstPacketLastLayer = firstParsedPacket.getLastLayer(); // to understand package protocol
    pcpp::TcpLayer* firstPacketTcpLayer = firstParsedPacket.getLayerOfType<pcpp::TcpLayer>(); // to find port

    unsigned int portDst = 0;
    unsigned int urgents = 0;
    unsigned int brokens = 0;
    unsigned int failedLogins = 0;
    bool loggedIn = false;
 
    bool isSrcSentSyn = false;
    bool isDstSentRst = false;

    if (!firstPacketTcpLayer == NULL)
        portDst = (int)ntohs(firstPacketTcpLayer->getTcpHeader()->portDst);

     /*
        ====================================================
        |Eth       |IPv4       |TCP       |Packet          |
        |Header    |Header     |Header    |Payload         |
        ====================================================

        |--------------------------------------------------|
        EthLayer data
                    |---------------------------------------|
                    IPv4Layer data
                                |---------------------------|
                                TcpLayer data
                                            |----------------|
                                            PayloadLayer data
    */

    std::vector<std::pair<pcpp::IPv4Address, pcpp::tcphdr*>> pkgSequence;
    do  // Connection level .PCAP splitted so 1 file = 1 connection
    {
        unsigned int data = 0;

        unsigned int hots = 0;


        // TODO now it doesn't work with IPv6Layer. So it may losts some results 
        pcpp::IPv4Address pkgIP;
        pcpp::tcphdr* pkgTcpFlag;

        // parse the raw packet into a parsed packet
        pcpp::Packet parsedPacket(&rawPacket);
        
        // go over all layers one by one and find out its type, its total length, its header length and its payload length
        for (pcpp::Layer* curLayer = parsedPacket.getFirstLayer(); curLayer != NULL; curLayer = curLayer->getNextLayer())
        {
            data += (int)curLayer->getDataLen();
            if(log)
            {
                std::cout << "Layer type: " 
                          << getProtocolTypeAsLDouble(curLayer->getProtocol())          // get layer type
                          << " Total data: "
                          << (int)curLayer->getDataLen()                                // get total length of the layer
                          << " Layer data: "
                          << (int)curLayer->getHeaderLen()                              // get the header length of the layer
                          << " Layer payload: "
                          << (int)curLayer->getLayerPayloadSize()                       // get the payload length of the layer (equals total length minus header length)
                          << std::endl;
            }
        }


        if(parsedPacket.getLayerOfType<pcpp::TcpLayer>() != NULL and parsedPacket.getLayerOfType<pcpp::TcpLayer>()->getTcpHeader()->urgFlag)
            ++urgents;
        if(parsedPacket.getLayerOfType<pcpp::IPv4Layer>() == NULL)
            ++brokens;
        if(parsedPacket.getLayerOfType<pcpp::HttpResponseLayer>() != NULL)
        {
            pcpp::HttpResponseLayer* httpResponse = parsedPacket.getLayerOfType<pcpp::HttpResponseLayer>();
            if(httpResponse->getFirstLine()->getStatusCode() ==  pcpp::HttpResponseLayer::Http401Unauthorized)
                ++failedLogins;
            if(httpResponse->getFirstLine()->getStatusCode() ==  pcpp::HttpResponseLayer::Http200OK)
                loggedIn = true;
        }

        if(parsedPacket.getLayerOfType<pcpp::IPv4Layer>() != NULL)
        {
            pkgIP = parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getSrcIpAddress();
            if(pkgIP == srcIP) sourceData += data;
            if(pkgIP == dstIP) destData += data;
        }

        // Get data from TCP Layer
        pcpp::TcpLayer* tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
        if( tcpLayer != NULL)
        {
            pkgTcpFlag = tcpLayer->getTcpHeader();
            pkgSequence.push_back(std::make_pair(pkgIP, pkgTcpFlag));
        }
        


    } while (reader->getNextPacket(rawPacket));
    
    // After connection analyze create a features string
    time_t end_conn = rawPacket.getPacketTimeStamp().tv_sec;

    features[0] = getFeature1(start_conn, end_conn);
    features[1] = getFeature2(firstPacketLastLayer->getProtocol());
    features[2] = portDst;
    features[3] = is_rej_flag(pkgSequence);
    features[4] = sourceData;
    features[5] = destData;
    features[6] = srcIP == dstIP ? 1.0f : 0.0f;
    features[7] = brokens;
    features[8] = urgents;
    features[9] = failedLogins;
    features[10] = loggedIn;

    // close the file reader and clean data
    pkgSequence.clear();
    reader->close();
}




void parse(char* path, long double arr[][FEATURES_AMOUNT])
{      
    // This is probably bad thing to do, but i don't actually know if directory_iterator provides interface
    // for iterating value
    int i = 0;

    for (const auto & entry : fs::directory_iterator(path))
    {
        std::cout << entry.path() << " is now parsing" << std::endl;
        readPcapFile(entry.path().string(), arr[i]);

        ++i;
    }
}

int main(int argc, char* argv[])
{
    if(argc != 4)
    {
        puts("Invalid input");
        exit(1);
    }

    setenv("PYTHONPATH", ".", 0);
    Py_Initialize();
    import_array();

    const int ND = 2;
    npy_intp dims[2]{SIZE, FEATURES_AMOUNT};
    long double(*c_arr)[FEATURES_AMOUNT]{ new long double[SIZE][FEATURES_AMOUNT] };
    for (int i = 0; i < SIZE; i++)
        for(int j = 0; j < FEATURES_AMOUNT; j++)
            c_arr[i][j] = .0f;

    parse(argv[1], c_arr);

    for (int i = 0; i < 30; i++)
    {
        for(int j = 0; j < 40; j++)
            std::cout << std::setprecision(0) << std::fixed << std::setw(4) << std::setfill(' ') << c_arr[i][j];
        std::cout << std::endl;
    }

    // //getPcapData(argv[1]);

    // for (int i = 0; i < SIZE; i++)
    //     c_arr[i] = i;

    // // Here we create numpy array from c array
    // PyObject *pArray = PyArray_SimpleNewFromData(ND, dims, NPY_LONGDOUBLE, reinterpret_cast<void*>(c_arr));

    // // Import mymodule
    // const char *module_name = argv[2];
    // PyObject *pName = PyUnicode_FromString(module_name);
    // PyObject *pModule = PyImport_Import(pName);
    // Py_DECREF(pName);

    // // Import function
    // const char *func_name = argv[3];
    // PyObject *pFunc = PyObject_GetAttrString(pModule, func_name);
    // PyObject *pReturn = PyObject_CallFunctionObjArgs(pFunc, pArray, NULL);
    // //PyFloatObject *np_ret = reinterpret_cast<PyFloatObject*>(pReturn);

    // // Convert back to C++ and print.
    // // int len = PyArray_SHAPE(np_ret)[0];
    // double c_out;
    // //c_out = reinterpret_cast<long double>(pReturn);
    // c_out = PyFloat_AsDouble(pReturn);
    // std::cout << "Printing output - C++" << std::endl;
    // std::cout << c_out << std::endl << std::endl;
    
    Py_Finalize();
    return 0;
}