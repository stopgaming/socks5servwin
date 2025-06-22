
#include <iostream>
#include <string>
#include <cstring>
#include <stdexcept>
#include <thread>
#include <atomic>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#endif

class Socks5GatewayProxy {
public:
    Socks5GatewayProxy(const std::string& listen_addr, uint16_t listen_port,
                     const std::string& gateway_addr)
        : listen_addr_(listen_addr), listen_port_(listen_port),
          gateway_addr_(gateway_addr), running_(false) {
#ifdef _WIN32
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            throw std::runtime_error("WSAStartup failed");
        }
#endif
    }

    ~Socks5GatewayProxy() {
        stop();
#ifdef _WIN32
        WSACleanup();
#endif
    }

    void start() {
        running_ = true;
        
        listen_sock_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listen_sock_ == INVALID_SOCKET) {
            throw std::runtime_error("Failed to create socket");
        }

        int optval = 1;
        setsockopt(listen_sock_, SOL_SOCKET, SO_REUSEADDR, 
                 (const char*)&optval, sizeof(optval));

        sockaddr_in server_addr{};
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(listen_port_);
        inet_pton(AF_INET, listen_addr_.c_str(), &server_addr.sin_addr);

        if (bind(listen_sock_, (sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
            throw std::runtime_error("Bind failed");
        }

        if (listen(listen_sock_, SOMAXCONN) == SOCKET_ERROR) {
            throw std::runtime_error("Listen failed");
        }

        std::cout << "SOCK5 gateway proxy listening on " << listen_addr_ << ":" << listen_port_ << std::endl;
        std::cout << "Routing through gateway: " << gateway_addr_ << std::endl;

        while (running_) {
            sockaddr_in client_addr{};
            socklen_t client_len = sizeof(client_addr);
            
            SOCKET client_sock = accept(listen_sock_, (sockaddr*)&client_addr, &client_len);
            if (client_sock == INVALID_SOCKET) {
                if (running_) {
                    std::cerr << "Accept failed" << std::endl;
                }
                continue;
            }

            char client_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
            std::cout << "Accepted connection from " << client_ip << std::endl;

            std::thread([this, client_sock]() {
                handle_client(client_sock);
            }).detach();
        }
    }

    void stop() {
        running_ = false;
        
        if (listen_sock_ != INVALID_SOCKET) {
#ifdef _WIN32
            closesocket(listen_sock_);
#else
            close(listen_sock_);
#endif
            listen_sock_ = INVALID_SOCKET;
        }
    }

private:
    struct Socks5Request {
        uint8_t ver;
        uint8_t cmd;
        uint8_t rsv;
        uint8_t atyp;
        std::string dst_addr;
        uint16_t dst_port;
    };

    void handle_client(SOCKET client_sock) {
        try {
            if (!socks5_handshake(client_sock)) {
                throw std::runtime_error("SOCK5 handshake failed");
            }

            Socks5Request request;
            if (!get_client_request(client_sock, request)) {
                throw std::runtime_error("Failed to get client request");
            }

            std::cout << "Connecting to " << request.dst_addr << ":" << request.dst_port 
                      << " via gateway " << gateway_addr_ << std::endl;

            SOCKET target_sock = connect_through_gateway(request);
            if (target_sock == INVALID_SOCKET) {
                send_failure_response(client_sock);
                throw std::runtime_error("Failed to connect to target");
            }

            send_success_response(client_sock);
            forward_data(client_sock, target_sock);
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;
        }

#ifdef _WIN32
        closesocket(client_sock);
#else
        close(client_sock);
#endif
    }

    SOCKET connect_through_gateway(const Socks5Request& request) {
        SOCKET target_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (target_sock == INVALID_SOCKET) {
            return INVALID_SOCKET;
        }

        // Устанавливаем шлюз через маршрутизацию
        sockaddr_in gateway_addr{};
        gateway_addr.sin_family = AF_INET;
        inet_pton(AF_INET, gateway_addr_.c_str(), &gateway_addr.sin_addr);

        // На Linux используем SO_BINDTODEVICE
#ifdef __linux__
        const char* iface = "eth0"; // Замените на нужный интерфейс
        if (setsockopt(target_sock, SOL_SOCKET, SO_BINDTODEVICE, iface, strlen(iface)) < 0) {
            close(target_sock);
            return INVALID_SOCKET;
        }
#endif

        // Настраиваем целевой адрес
        sockaddr_in target_addr{};
        target_addr.sin_family = AF_INET;
        target_addr.sin_port = htons(request.dst_port);

        if (request.atyp == 0x01) { // IPv4
            inet_pton(AF_INET, request.dst_addr.c_str(), &target_addr.sin_addr);
        } else { // Доменное имя
            addrinfo hints{}, *res;
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;

            if (getaddrinfo(request.dst_addr.c_str(), nullptr, &hints, &res) != 0) {
#ifdef _WIN32
                closesocket(target_sock);
#else
                close(target_sock);
#endif
                return INVALID_SOCKET;
            }
            target_addr.sin_addr = ((sockaddr_in*)res->ai_addr)->sin_addr;
            freeaddrinfo(res);
        }

        // На Windows добавляем маршрут
#ifdef _WIN32
        MIB_IPFORWARDROW route;
        memset(&route, 0, sizeof(route));
        route.dwForwardDest = target_addr.sin_addr.s_addr;
        route.dwForwardMask = inet_addr("255.255.255.255");
        route.dwForwardNextHop = gateway_addr.sin_addr.s_addr;
        route.dwForwardIfIndex = 0; // Автовыбор интерфейса
        route.dwForwardType = 4;    // Next hop
        route.dwForwardProto = 3;   // PROTO_IP_NETMGMT
        route.dwForwardAge = 0;
        route.dwForwardMetric1 = 1;

        if (CreateIpForwardEntry(&route) != NO_ERROR) {
            // Если маршрут уже существует, продолжаем
        }
#endif

        // Пробуем подключиться
        if (connect(target_sock, (sockaddr*)&target_addr, sizeof(target_addr)) == SOCKET_ERROR) {
#ifdef _WIN32
            closesocket(target_sock);
#else
            close(target_sock);
#endif
            return INVALID_SOCKET;
        }

        return target_sock;
    }

    bool socks5_handshake(SOCKET client_sock) {
        unsigned char buf[256];
        int bytes = recv(client_sock, (char*)buf, 2, 0);
        if (bytes != 2 || buf[0] != 0x05) return false;

        int nmethods = buf[1];
        bytes = recv(client_sock, (char*)buf, nmethods, 0);
        if (bytes != nmethods) return false;

        bool no_auth = false;
        for (int i = 0; i < nmethods; i++) {
            if (buf[i] == 0x00) no_auth = true;
        }

        if (!no_auth) {
            buf[0] = 0x05; buf[1] = 0xFF;
            send(client_sock, (char*)buf, 2, 0);
            return false;
        }

        buf[0] = 0x05; buf[1] = 0x00;
        send(client_sock, (char*)buf, 2, 0);
        return true;
    }

    bool get_client_request(SOCKET client_sock, Socks5Request& request) {
        unsigned char buf[256];
        
        int bytes = recv(client_sock, (char*)buf, 4, 0);
        if (bytes != 4 || buf[0] != 0x05) return false;

        request.ver = buf[0];
        request.cmd = buf[1];
        request.rsv = buf[2];
        request.atyp = buf[3];

        if (request.cmd != 0x01) {
            send_command_not_supported(client_sock);
            return false;
        }

        if (request.atyp == 0x01) { // IPv4
            bytes = recv(client_sock, (char*)buf, 6, 0);
            if (bytes != 6) return false;

            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, buf, ip, INET_ADDRSTRLEN);
            request.dst_addr = ip;
            request.dst_port = (buf[4] << 8) | buf[5];
        } else if (request.atyp == 0x03) { // Domain name
            bytes = recv(client_sock, (char*)buf, 1, 0);
            if (bytes != 1) return false;

            int len = buf[0];
            bytes = recv(client_sock, (char*)buf, len + 2, 0);
            if (bytes != len + 2) return false;

            request.dst_addr = std::string((char*)buf, len);
            request.dst_port = (buf[len] << 8) | buf[len + 1];
        } else {
            return false;
        }

        return true;
    }

    void send_success_response(SOCKET client_sock) {
        unsigned char buf[10] = {0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        send(client_sock, (char*)buf, 10, 0);
    }

    void send_failure_response(SOCKET client_sock) {
        unsigned char buf[10] = {0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        send(client_sock, (char*)buf, 10, 0);
    }

    void send_command_not_supported(SOCKET client_sock) {
        unsigned char buf[10] = {0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        send(client_sock, (char*)buf, 10, 0);
    }

    void forward_data(SOCKET src_sock, SOCKET dst_sock) {
        fd_set readfds;
        char buf[4096];
        
        while (running_) {
            FD_ZERO(&readfds);
            FD_SET(src_sock, &readfds);
            FD_SET(dst_sock, &readfds);
            
            int max_fd = std::max(src_sock, dst_sock);
            
            int activity = select(max_fd + 1, &readfds, nullptr, nullptr, nullptr);
            if (activity <= 0) break;
            
            if (FD_ISSET(src_sock, &readfds)) {
                int bytes = recv(src_sock, buf, sizeof(buf), 0);
                if (bytes <= 0) break;
                send(dst_sock, buf, bytes, 0);
            }
            
            if (FD_ISSET(dst_sock, &readfds)) {
                int bytes = recv(dst_sock, buf, sizeof(buf), 0);
                if (bytes <= 0) break;
                send(src_sock, buf, bytes, 0);
            }
        }
        
#ifdef _WIN32
        closesocket(src_sock);
        closesocket(dst_sock);
#else
        close(src_sock);
        close(dst_sock);
#endif
    }

private:
    std::string listen_addr_;
    uint16_t listen_port_;
    std::string gateway_addr_;
    std::atomic<bool> running_;
    SOCKET listen_sock_ = INVALID_SOCKET;
};

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <listen_addr> <listen_port> <gateway_addr>" << std::endl;
        return 1;
    }

    try {
        Socks5GatewayProxy proxy(argv[1], static_cast<uint16_t>(std::stoi(argv[2])), argv[3]);
        proxy.start();
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
