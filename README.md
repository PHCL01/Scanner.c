# Scanner.c
varredura de endereços IP em busca de outros dispositivos
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include "scanner.h"

void* scan_port(void* arg) {
    scan_data* data = (scan_data*)arg;
    int sock;
    struct sockaddr_in server;

    // 1. Criação do Socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        free(data); // Libera memória se o socket falhar
        return NULL;
    }

    // 2. Configuração de Timeouts (Essencial para não travar a rede do banco)
    struct timeval timeout;
    timeout.tv_sec = 1; 
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr(data->ip);
    server.sin_port = htons(data->port);

    // 3. Tentativa de Conexão
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) == 0) {
        printf("[+] PORTA %-5d | STATUS: ABERTA | ALVO: %s\n", data->port, data->ip);
        
        // Banner Grabbing Seguro
        char buffer[128];
        memset(buffer, 0, sizeof(buffer));
        // Envia um probe genérico (ex: para HTTP)
        send(sock, "GET / HTTP/1.0\r\n\r\n", 18, 0);
        
        int bytes_received = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes_received > 0) {
            // Limpa caracteres não imprimíveis para evitar quebra do terminal
            for(int i = 0; i < bytes_received; i++) {
                if(buffer[i] < 32 || buffer[i] > 126) buffer[i] = ' ';
            }
            printf("    |--> Identificado: %s\n", buffer);
        }
    }

    // 4. Limpeza Crítica (Prevenção de Leaks)
    close(sock); // Fecha o descritor de arquivo
    free(data);  // Libera a memória alocada no main.c
    return NULL;
}
