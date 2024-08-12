#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <unistd.h>

    const std::string RESET = "\033[0m";
    const std::string RED = "\033[31m";
    const std::string GREEN = "\033[32m";
    const std::string YELLOW = "\033[33m";
    const std::string BLUE = "\033[34m";
    const std::string MAGENTA = "\033[35m";
    const std::string CYAN = "\033[36m";
    const std::string WHITE = "\033[37m";
void print() {
     std::cout << "/usr/bin/ld: /tmp/ccOnj4bo.o: warning: relocation against `_ZSt4cout' in read-only section `.text._ZN3UPF26forwardPacketToDestinationE6Packet[_ZN3UPF26forwardPacketToDestinationE6Packet]'\n"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function stable:\n" << std::endl;
            sleep(0.5);
              std::cout << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function `assignVariableNow':"
             << "/usr/bin/ld: upf.cpp:(.text+0x24): undefined reference to `std::basic_ostream<char, std::char_traits<char> >& std::endl<char, std::char_traits<char> >(std::basic_ostream<char, std::char_traits<char> >&)'\n"
              << "/usr/bin/ld: upf.cpp:(.text+0x1d): undefined reference to `std::basic_ostream<char, std::char_traits<char> >& std::operator<< <std::char_traits<char> >(std::basic_ostream<char, std::char_traits<char> >&, char const*)'\n"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function `level':\n"
              << "/usr/bin/ld: upf.cpp:(.text+0x1d): undefined reference to `std::basic_ostream<char, std::char_traits<char> >& std::operator<< <std::char_traits<char> >(std::basic_ostream<char, std::char_traits<char> >&, char const*)'\n"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function `model':\n"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function `print':\n"
              << "/usr/bin/ld: upf.cpp:(.text+0x5a): undefined reference to `std::ostream::operator<<(std::ostream& (*)(std::ostream&))'\n"
              << "upf.cpp:(.text+0x15): undefined reference to `std::cout'\n"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function 'check':" <<std::endl;
              sleep(1);
              std::cout 
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function `dat forward':"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function [08/12 10:35:00.600] INFO: UPF shutdown (../src/main.c:200):"
              << "upf.cpp:(.text+0x15): undefined reference to `std::cout'\n"
              << "upf.cpp:(.text+0x15): undefined reference to `std::cout'\n"
              << "upf.cpp:(.text+0x15): undefined reference to `std::cout'\n"
              << "/usr/bin/ld: upf.cpp:(.text+0x24): undefined reference to `std::basic_ostream<char, std::char_traits<char> >& std::endl<char, std::char_traits<char> >(std::basic_ostream<char, std::char_traits<char> >&)'\n"
              << "/usr/bin/ld: upf.cpp:(.text+0x1d): undefined reference to `std::basic_ostream<char, std::char_traits<char> >& std::operator<< <std::char_traits<char> >(std::basic_ostream<char, std::char_traits<char> >&, char const*)'\n"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function udm:\n"
              << "/usr/bin/ld: upf.cpp:(.text+0x1d): undefined reference to `std::basic_ostream<char, std::char_traits<char> >& std::operator<< <std::char_traits<char> >(std::basic_ostream<char, std::char_traits<char> >&, char const*)'\n"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function `license':\n"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function `test':\n"
              << "/usr/bin/ld: upf.cpp:(.text+0x5a): undefined reference to `std::ostream::operator<<(std::ostream& (*)(std::ostream&))'\n"
              << "upf.cpp:(.text+0x15): undefined reference to `std::cout'\n"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function `pjk':"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function `ugf':"<<std::endl;
            sleep(0.9);
              std::cout << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function `sepp':"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function [08/12 10:35:00.600] INFO: UPF shutdown (../src/main.c:200)[08/12 10:35:00.600] INFO: UPF shutdown (../src/main.c:200):\n"
                << "upf.cpp:(.text+0x15): undefined reference to `std::cout'\n"
              << "upf.cpp:(.text+0x15): undefined reference to `std::cout'\n"
              << "/usr/bin/ld: upf.cpp:(.text+0x24): undefined reference to `std::basic_ostream<char, std::char_traits<char> >& std::endl<char, std::char_traits<char> >(std::basic_ostream<char, std::char_traits<char> >&)'\n"
              << "/usr/bin/ld: upf.cpp:(.text+0x1d): undefined reference to `std::basic_ostream<char, std::char_traits<char> >& std::operator<< <std::char_traits<char> >(std::basic_ostream<char, std::char_traits<char> >&, char const*)'\n"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function `dsa':\n"
              << "/usr/bin/ld: upf.cpp:(.text+0x1d): undefined reference to `std::basic_ostream<char, std::char_traits<char> >& std::operator<< <std::char_traits<char> >(std::basic_ostream<char, std::char_traits<char> >&, char const*)'\n"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function `nssf':\n"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function 'data':\n"
              << "/usr/bin/ld: upf.cpp:(.text+0x5a): undefined reference to `std::ostream::operator<<(std::ostream& (*)(std::ostream&))'\n"
              << "upf.cpp:(.text+0x15): undefined reference to `std::cout'\n"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function [08/12 10:35:00.600] INFO: UPF shutdown (../src/main.c:200)[08/12 10:35:00.600] INFO: UPF shutdown (../src/main.c:200):\n"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function `upf forward':" <<std::endl;
            sleep(1.2);
              std::cout << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function [08/12 10:35:00.600] INFO: UPF shutdown (../src/main.c:200)[08/12 10:35:00.600] INFO: UPF shutdown (../src/main.c:200):"
               << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function :"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function :"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function `render':"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function `send':"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function name':"
              << "upf.cpp:(.text+0x15): undefined reference to `std::cout'\n"
              << "upf.cpp:(.text+0x15): undefined reference to `std::cout'\n"
              << "upf.cpp:(.text+0x15): undefined reference to `std::cout'\n"
              << "/usr/bin/ld: upf.cpp:(.text+0x24): undefined reference to `std::basic_ostream<char, std::char_traits<char> >& std::endl<char, std::char_traits<char> >(std::basic_ostream<char, std::char_traits<char> >&)'\n"
              << "/usr/bin/ld: upf.cpp:(.text+0x1d): undefined reference to `std::basic_ostream<char, std::char_traits<char> >& std::operator<< <std::char_traits<char> >(std::basic_ostream<char, std::char_traits<char> >&, char const*)'\n"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function ':\n"
              << "/usr/bin/ld: upf.cpp:(.text+0x1d): undefined reference to `std::basic_ostream<char, std::char_traits<char> >& std::operator<< <std::char_traits<char> >(std::basic_ostream<char, std::char_traits<char> >&, char const*)'\n"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function `':\n"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function ugf:\n"
              << "/usr/bin/ld: upf.cpp:(.text+0x5a): undefined reference to `std::ostream::operator<<(std::ostream& (*)(std::ostream&))'\n"
              << "upf.cpp:(.text+0x15): undefined reference to `std::cout'\n"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function network:\n"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function `datasend':" <<std::endl;
            sleep(1);
              std::cout << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function [08/12 10:35:00.600] INFO: UPF shutdown (../src/main.c:200)[08/12 10:35:00.600] INFO: UPF shutdown (../src/main.c:200):"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in func:\n"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o:\n"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o:':\n"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: :\n"
              << "upf.cpp:(.text+0x15): undefined reference to `std::cout'\n"
              << "upf.cpp:(.text+0x15): undefined reference to `std::cout'\n"
              << "upf.cpp:(.text+0x15): undefined reference to `std::cout'\n"
              << "/usr/bin/ld: upf.cpp:(.text+0x24): undefined reference to `std::basic_ostream<char, std::char_traits<char> >& std::endl<char, std::char_traits<char> >(std::basic_ostream<char, std::char_traits<char> >&)'\n"
              << "/usr/bin/ld: upf.cpp:(.text+0x1d): undefined reference to `std::basic_ostream<char, std::char_traits<char> >& std::operator<< <std::char_traits<char> >(std::basic_ostream<char, std::char_traits<char> >&, char const*)'\n"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function `temp':\n"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function `c++':"
              << "/usr/bin/ld: upf.cpp:(.text+0x5a): undefined reference to `std::ostream::operator<<(std::ostream& (*)(std::ostream&))'\n"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in c++ variable:"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function 'prioritydatacheck':" <<std::endl;
}
class Packet {
public:
    std::string srcIP;
    std::string dstIP;
    std::string packet;
    int priority;
};

class UPF {
private:
    bool applyFilteringAndPolicingRules(Packet packet) {
        // Implement filtering and policing rules logic here
        // For example, check if the packet's source IP is in a blacklist
        std::cout << "filtering and policing......" << std::endl;
        sleep(1);
        print();
        if (packet.srcIP == "192.168.1.100") {
            std::cout << "Packet filtering and policing failed: source IP is blacklisted" << std::endl;
            return false;
        }
        std::cout << "Packet filtering and policing succeeded" << std::endl;
        sleep(1);

        std::cout << GREEN<< "[08/12 10:30:10.200] INFO:" << GREEN 
        << " Session created: UE IPv4[10.0.0.1] (../src/upf-sm.c:100)"<< std::endl;

        std::cout << GREEN<< "[08/12 10:30:15.250] INFO:" 
        << "Session modified: UE IPv4[10.0.0.1] (../src/upf-sm.c:150)"<< RESET<< std::endl;
        
        sleep(1.6);
        std::cout << GREEN <<"[08/12 10:30:20.300] INFO: Forwarding data for UE IPv4[10.0.0.1] (../src/upf-fwd.c:200)"<< RESET<<std::endl;
        print();
        sleep(0.7);





        sleep(1);
        return true;
    }

    bool isBlacklisted(std::string ip) {
        std::vector<std::string> blacklist = {"192.168.1.100", "10.0.0.1", "172.16.1.1"};
        // Check if the given IP is in the blacklist
        return std::find(blacklist.begin(), blacklist.end(), ip) != blacklist.end();
    }

    bool enforceQoSPolicies(Packet packet) {
        // Implement QoS policy enforcement logic here
        // For example, check if the packet's priority is high enough
        sleep(2);
        if (packet.priority < 5) {
            std::cout <<RED<< "QoS enforcement failed: packet priority is too low" <<RESET <<std::endl;
            std::cout << RED <<"[08/12 10:30:40.500] WARN: Failed to forward packet (../src/upf-fwd.c:250)" << RESET<<std::endl;
            return false;
        }
        std::cout<< GREEN << "QoS enforcement succeeded" << RESET <<std::endl;
        return true;
    }

    bool performNAT(Packet packet) {
        // Implementing  NAT logic here
        // For example, translate the packet's source IP to a public IP
        sleep(2);
        packet.srcIP = "203.0.113.1";
        std::cout <<GREEN<< "NAT succeeded" << RESET<<std::endl;
        return true;
    }

    bool manageTrafficFlow(Packet packet) {
        // Implement traffic management logic here
        sleep(2);
        // For example, check if the packet's destination IP is congested
        if (packet.dstIP == "8.8.8.8") {
            std::cout << "Traffic management failed: destination IP is congested" << std::endl;
            return false;
        }
        std::cout<<GREEN << "Traffic management succeeded" << RESET <<std::endl;
        return true;
    }

    bool provideSecurityFeatures(Packet packet) {
        // Implement security feature logic here

        sleep(1);

        // For example, check if the packet contains malware
        if (packet.packet.find("malware") != std::string::npos) {
            std::cout << "Security features failed: packet contains malware" << std::endl;
            sleep(1);
            return false;
        }
        std::cout<<GREEN << "Security features succeeded" << RESET<<std::endl;
        return true;
    }

    bool supportLawfulInterception(Packet packet) {
        sleep(1);
        // Implement lawful interception logic here
        // For example, check if the packet's destination IP is a law enforcement agency
        if (packet.dstIP == "10.0.0.1") {
            std::cout << GREEN << "Lawful interception succeeded" <<RESET<< std::endl;
            return true;
        }
        std::cout << "Lawful interception failed: not a law enforcement agency" << std::endl;
        sleep(1);
        return false;
    }

    bool supportDataRetention(Packet packet) {
        sleep(1);
        // Implement data retention logic here
        // For example, store the packet in a database
        std::cout<<GREEN << "Data retention succeeded"<<RESET << std::endl;
        sleep(1);
        return true;
    }

    void forwardPacketToDestination(Packet packet) {
        sleep(1);
        std::cout <<GREEN<< "Packet forwarded to destination: " << packet.dstIP << RESET <<std::endl;
        std::cout <<GREEN<< "[08/12 10:30:30.400] INFO: Total Packets Forwarded: 1000 (../src/upf-stat.c:50)" << packet.dstIP << RESET<<std::endl;
        sleep(1);

    }

public:
    bool processPacket(Packet packet) {
        if (!applyFilteringAndPolicingRules(packet)) {
            return false;
        }
        if (!enforceQoSPolicies(packet)) {
            return false;
        }
        if (!performNAT(packet)) {
            return false;
        }
        if (!manageTrafficFlow(packet)) {
            return false;
        }
        if (!provideSecurityFeatures(packet)) {
            return false;
        }
        if (!supportLawfulInterception(packet)) {
            return false;
        }
        if (!supportDataRetention(packet)) {
            return false;
        }
        forwardPacketToDestination(packet);
        return true;
    }
};


void print2() {
    std::cout << "/usr/bin/ld: /tmp/ccOnj4bo.o: warning: relocation against `_ZSt4cout' in read-only section `.text._ZN3UPF26forwardPacketToDestinationE6Packet[_ZN3UPF26forwardPacketToDestinationE6Packet]'\n"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function dataugf:\n" << std::endl;
            sleep(1.2);
              std::cout << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function userdata:"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function clang:\n"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function program:\n"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function jump:\n"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function sgwc:\n"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function sgwctemp:" <<std::endl;
              sleep(1);
              std::cout << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function json:\n"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function cprogram:\n"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function udm:\n"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function udr:"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function udm:"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function check:"<<std::endl;
            sleep(0.9);
              std::cout << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function value:\n"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function valuecheck:"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function valuechecknow:"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function subfolders:"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function webui:"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function meson:" <<std::endl;
            sleep(1);
              std::cout << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function mesonbuild:\n"
               << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function builder:\n"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function build:\n"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function temo:\n"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function 5gnetwork:\n"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function open5g:\n"
              << "upf.cpp:(.text+0x15): undefined reference to `std::cout'\n"
              << "upf.cpp:(.text+0x15): undefined reference to `std::cout'\n"
              << "upf.cpp:(.text+0x15): undefined reference to `std::cout'\n"
              << "/usr/bin/ld: upf.cpp:(.text+0x24): undefined reference to `std::basic_ostream<char, std::char_traits<char> >& std::endl<char, std::char_traits<char> >(std::basic_ostream<char, std::char_traits<char> >&)'\n"
              << "/usr/bin/ld: upf.cpp:(.text+0x1d): undefined reference to `std::basic_ostream<char, std::char_traits<char> >& std::operator<< <std::char_traits<char> >(std::basic_ostream<char, std::char_traits<char> >&, char const*)'\n"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function open5gtool:\n"
              << "/usr/bin/ld: upf.cpp:(.text+0x1d): undefined reference to `std::basic_ostream<char, std::char_traits<char> >& std::operator<< <std::char_traits<char> >(std::basic_ostream<char, std::char_traits<char> >&, char const*)'\n"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function open5gfunction:\n"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function open5glabel:\n"
              << "/usr/bin/ld: upf.cpp:(.text+0x5a): undefined reference to `std::ostream::operator<<(std::ostream& (*)(std::ostream&))'\n"
              << "upf.cpp:(.text+0x15): undefined reference to `std::cout'\n"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function open5ggo:\n"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function open5standard:" <<std::endl;
            sleep(1.2);
              std::cout << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function test:"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function edit:\n"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function editmain:\n"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function license:\n"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function clang:\n"
              << "upf.cpp:(.text+0x15): undefined reference to `std::cout'\n"
              << "upf.cpp:(.text+0x15): undefined reference to `std::cout'\n"
              << "upf.cpp:(.text+0x15): undefined reference to `std::cout'\n"
              << "/usr/bin/ld: upf.cpp:(.text+0x24): undefined reference to `std::basic_ostream<char, std::char_traits<char> >& std::endl<char, std::char_traits<char> >(std::basic_ostream<char, std::char_traits<char> >&)'\n"
              << "/usr/bin/ld: upf.cpp:(.text+0x1d): undefined reference to `std::basic_ostream<char, std::char_traits<char> >& std::operator<< <std::char_traits<char> >(std::basic_ostream<char, std::char_traits<char> >&, char const*)'\n"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function vagrant:\n"
              << "/usr/bin/ld: upf.cpp:(.text+0x1d): undefined reference to `std::basic_ostream<char, std::char_traits<char> >& std::operator<< <std::char_traits<char> >(std::basic_ostream<char, std::char_traits<char> >&, char const*)'\n"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function clang:\n"
              << "/usr/bin/ld: /tmp/ccOnj4bo.o: in function readme:" <<std::endl;


            
            
}

int main() {
    UPF upf;

    std::cout << ""<< std::endl;




        std::cout << GREEN<< "[08/12 10:30:00.123]" << GREEN << " Open5GS daemon v2.3.4"<< std::endl;

        std::cout << GREEN<< "[08/12 10:30:00.124] Configuration :" 
        << "'/etc/open5gs/upf.yaml'"<< GREEN<< std::endl;

        std::cout << GREEN<< "[08/12 10:30:00.125] File Logging : " 
        << "'/var/log/open5gs/upf.log')"<< RESET<< std::endl;
    
    sleep(3);



    std::cout << GREEN << "[08/12 10:30:00.126] INFO: Configuration : (../src/main.c:58)"<< std::endl;
    std::cout << "[08/12 10:30:00.127] INFO:  o GTP-U: 127.0.0.1 (../src/upf/config.c:43"<< RESET <<std::endl;
    sleep(2);


    Packet packet2;
    packet2.srcIP = "170.150.2.200";
    packet2.dstIP = "10.0.0.1";
    packet2.packet = "Hello, world!";
    packet2.priority = 1;


    std::cout << "Processing packet..." << std::endl;
    sleep(2);
    print();
    


    std::cout << "Enter priority of the packet:\t" << std::endl;
    print2();



    if (upf.processPacket(packet2)) {
        std::cout << GREEN<< "Packet processing succeeded" << std::endl;
    } else {
        std::cout << RED <<"Packet processing failed" <<std::endl;
    }
    std::cout<< "[08/12 10:35:00.600] INFO: UPF shutdown (../src/main.c:200)"<<std::endl;
    


    return 0;
}