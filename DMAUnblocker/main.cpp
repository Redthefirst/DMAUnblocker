#include <iostream>
#include <iomanip>
#include <cstdint>
#include <string>
#include "Exploit/fbiosdrvExploit.hpp"
#include <vector>
#include <thread>
#include <chrono>

// PCI Configuration Address and Data ports
#define PCI_CONFIG_ADDRESS  0xCF8
#define PCI_CONFIG_DATA     0xCFC

// PCI Command Register bits
#define PCI_COMMAND_BUS_MASTER  0x04
#define PCI_COMMAND_MEMORY      0x02
#define PCI_COMMAND_IO          0x01

struct PCIDevice {
    uint8_t bus;
    uint8_t device;
    uint8_t function;
    uint16_t vendor_id;
    uint16_t device_id;
    std::string description;
};

uint32_t MakePCIAddress(uint8_t bus, uint8_t device, uint8_t function, uint8_t offset) {
    return 0x80000000 | (bus << 16) | (device << 11) | (function << 8) | (offset & 0xFC);
}

uint32_t ReadPCIConfig(uint8_t bus, uint8_t device, uint8_t function, uint8_t offset) {
    uint32_t address = MakePCIAddress(bus, device, function, offset);
    fbiosdrvExploit::WritePort(PCI_CONFIG_ADDRESS, address, 4);
    return fbiosdrvExploit::ReadPort(PCI_CONFIG_DATA, 4);
}

void WritePCIConfig(uint8_t bus, uint8_t device, uint8_t function, uint8_t offset, uint32_t value) {
    uint32_t address = MakePCIAddress(bus, device, function, offset);
    fbiosdrvExploit::WritePort(PCI_CONFIG_ADDRESS, address, 4);
    fbiosdrvExploit::WritePort(PCI_CONFIG_DATA, value, 4);
}

uint16_t ReadPCICommand(uint8_t bus, uint8_t device, uint8_t function) {
    uint32_t config = ReadPCIConfig(bus, device, function, 0x04);
    return config & 0xFFFF;
}

void WritePCICommand(uint8_t bus, uint8_t device, uint8_t function, uint16_t command) {
    uint32_t config = ReadPCIConfig(bus, device, function, 0x04);
    config = (config & 0xFFFF0000) | command;
    WritePCIConfig(bus, device, function, 0x04, config);
}

std::vector<PCIDevice> ScanPCIDevices() {
    std::vector<PCIDevice> devices;

    for (int bus = 0; bus < 256; bus++) {
        for (int device = 0; device < 32; device++) {
            for (int function = 0; function < 8; function++) {
                uint32_t config = ReadPCIConfig(bus, device, function, 0x00);
                uint16_t vendor_id = config & 0xFFFF;
                uint16_t device_id = (config >> 16) & 0xFFFF;

                if (vendor_id != 0xFFFF && vendor_id != 0x0000) {
                    PCIDevice dev;
                    dev.bus = bus;
                    dev.device = device;
                    dev.function = function;
                    dev.vendor_id = vendor_id;
                    dev.device_id = device_id;

                    uint32_t class_code = ReadPCIConfig(bus, device, function, 0x08);
                    uint8_t base_class = (class_code >> 24) & 0xFF;
                    uint8_t sub_class = (class_code >> 16) & 0xFF;

                    if (base_class == 0x02 && sub_class == 0x80) {
                        dev.description = "Network Controller (WiFi)";
                    }
                    else if (base_class == 0x02) {
                        dev.description = "Network Controller";
                    }
                    else {
                        dev.description = "Unknown Device";
                    }

                    devices.push_back(dev);
                }
            }
        }
    }
    return devices;
}

void EnableBusMastering(uint8_t bus, uint8_t device, uint8_t function) {
    uint16_t command = ReadPCICommand(bus, device, function);

    std::cout << "Current PCI Command: 0x" << std::hex << command << std::dec << std::endl;
    std::cout << "Bus Mastering: " << ((command & PCI_COMMAND_BUS_MASTER) ? "ENABLED" : "DISABLED") << std::endl;
    std::cout << "Memory Space: " << ((command & PCI_COMMAND_MEMORY) ? "ENABLED" : "DISABLED") << std::endl;
    std::cout << "I/O Space: " << ((command & PCI_COMMAND_IO) ? "ENABLED" : "DISABLED") << std::endl;

    if (!(command & PCI_COMMAND_BUS_MASTER)) {
        std::cout << "\nEnabling Bus Mastering..." << std::endl;
        command |= PCI_COMMAND_BUS_MASTER | PCI_COMMAND_MEMORY;
        WritePCICommand(bus, device, function, command);

        uint16_t new_command = ReadPCICommand(bus, device, function);
        std::cout << "New PCI Command: 0x" << std::hex << new_command << std::dec << std::endl;
        std::cout << "Bus Mastering: " << ((new_command & PCI_COMMAND_BUS_MASTER) ? "ENABLED" : "DISABLED") << std::endl;
    }
    else {
        std::cout << "Bus Mastering already enabled!" << std::endl;
    }
}

int main() {
    if (!fbiosdrvExploit::LoadDriver()) {
        std::cerr << "Failed to load driver\n";
        return 1;
    }

    std::cout << "Scanning PCI devices...\n" << std::endl;
    auto devices = ScanPCIDevices();

    std::cout << "Found PCI Devices:" << std::endl;
    for (size_t i = 0; i < devices.size(); i++) {
        std::cout << i << ": Bus " << (int)devices[i].bus
            << ", Device " << (int)devices[i].device
            << ", Function " << (int)devices[i].function
            << " - " << std::hex << devices[i].vendor_id << ":" << devices[i].device_id << std::dec
            << " (" << devices[i].description << ")" << std::endl;
    }

    std::cout << "\nEnter device number to enable bus mastering (or -1 to exit): ";
    int choice;
    std::cin >> choice;

    if (choice >= 0 && choice < devices.size()) {
        PCIDevice& dev = devices[choice];
        std::cout << "\nSelected: " << dev.description << std::endl;
        while (true) {
            std::cout << "Device Fixed\n";
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            EnableBusMastering(dev.bus, dev.device, dev.function);
        }
    }

    fbiosdrvExploit::CloseDriver();
    return 0;
}
