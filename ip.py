from iputils import *
import ipaddress
import struct

class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            next_hop = self._next_hop(dst_addr)
            
            # Trata corretamente o campo TTL do datagrama
            if ttl > 1:
                # Decrementa TTL (Passo 4)
                novo_ttl = ttl - 1
                novo_datagrama = datagrama[:8] + bytes([novo_ttl]) + datagrama[9:]
                novo_datagrama = novo_datagrama[:10] + b'\x00\x00' + novo_datagrama[12:]
                checksum = calc_checksum(novo_datagrama[:20])
                novo_datagrama = novo_datagrama[:10] + struct.pack('!H', checksum) + novo_datagrama[12:]
                
                self.enlace.enviar(novo_datagrama, next_hop)
                
            else:
                # Passo 5: TTL chegou a 1 (ou menos) - expirou na nossa mão
                # Descarta o pacote e gera um ICMP Time Exceeded
                
                # 1. Payload do ICMP = Cabeçalho IP original + 8 primeiros bytes de dados.
                # Extrai o tamanho do cabeçalho a partir do IHL (bits 4-7 do primeiro byte)
                ihl = datagrama[0] & 0x0f
                tamanho_cabecalho = ihl * 4
                payload_icmp = datagrama[:tamanho_cabecalho + 8]
                
                # 2. Cabeçalho ICMP (Type 11, Code 0)
                # Formato: !BBHI (1 byte Type, 1 byte Code, 2 bytes Checksum, 4 bytes Unused)
                icmp_header_sem_checksum = struct.pack('!BBHI', 11, 0, 0, 0)
                
                # 3. Calcula o Checksum do ICMP
                icmp_segment = icmp_header_sem_checksum + payload_icmp
                checksum_icmp = calc_checksum(icmp_segment)
                
                # Refaz o cabeçalho ICMP com o checksum gerado
                icmp_header = struct.pack('!BBHI', 11, 0, checksum_icmp, 0)
                icmp_datagrama = icmp_header + payload_icmp
                
                # 4. Monta o cabeçalho IPv4 para a mensagem de resposta
                # A resposta sai do self.meu_endereco para o src_addr
                version_ihl = (4 << 4) | 5
                dscp_ecn = 0
                total_len = 20 + len(icmp_datagrama)
                identification = 0
                flags_frag_offset = 0
                ttl_resposta = 64
                proto_resposta = IPPROTO_ICMP  # Protocolo agora é 1 (ICMP)
                checksum_ip = 0
                
                cabecalho_ip_sem_checksum = struct.pack('!BBHHHBBH4s4s',
                                                        version_ihl,
                                                        dscp_ecn,
                                                        total_len,
                                                        identification,
                                                        flags_frag_offset,
                                                        ttl_resposta,
                                                        proto_resposta,
                                                        checksum_ip,
                                                        str2addr(self.meu_endereco),
                                                        str2addr(src_addr))
                
                # Calcula o checksum do pacote IPv4 da resposta
                checksum_ip = calc_checksum(cabecalho_ip_sem_checksum)
                cabecalho_ip = cabecalho_ip_sem_checksum[:10] + struct.pack('!H', checksum_ip) + cabecalho_ip_sem_checksum[12:]
                
                # Junta tudo
                datagrama_resposta = cabecalho_ip + icmp_datagrama
                
                # 5. Envia o pacote final de volta utilizando o next hop para a origem
                next_hop_resposta = self._next_hop(src_addr)
                if next_hop_resposta is not None:
                    self.enlace.enviar(datagrama_resposta, next_hop_resposta)

    def _next_hop(self, dest_addr):
        dest_ip = ipaddress.ip_address(dest_addr)
        melhor_rede = None
        melhor_next_hop = None

        for cidr, next_hop in self.tabela:
            rede = ipaddress.ip_network(cidr)

            if dest_ip in rede and (melhor_rede is None or rede.prefixlen > melhor_rede.prefixlen):
                melhor_rede = rede
                melhor_next_hop = next_hop

        return melhor_next_hop

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        self.tabela = tabela

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)
        
        # Monta o datagrama IPv4 com payload TCP
        # Cabeçalho IPv4: version(4bits) + IHL(4bits) + DSCP(6bits) + ECN(2bits) + ...
        version_ihl = (4 << 4) | 5  # IPv4, IHL=5 (20 bytes)
        dscp_ecn = 0  # DSCP=0, ECN=0
        total_len = 20 + len(segmento)  # Tamanho do cabeçalho + payload
        identification = 0
        flags_frag_offset = 0  # Flags=0, Frag offset=0
        ttl = 64
        proto = IPPROTO_TCP
        checksum = 0  # Será calculado depois
        
        # Converte endereços de string para bytes
        src_addr_bytes = str2addr(self.meu_endereco)
        dst_addr_bytes = str2addr(dest_addr)
        
        # Monta o cabeçalho IPv4 sem checksum (checksum=0)
        cabecalho = struct.pack('!BBHHHBBH4s4s',
                                version_ihl,
                                dscp_ecn,
                                total_len,
                                identification,
                                flags_frag_offset,
                                ttl,
                                proto,
                                checksum,
                                src_addr_bytes,
                                dst_addr_bytes)
        
        # Calcula o checksum do cabeçalho
        checksum = calc_checksum(cabecalho)
        
        # Reinsere o checksum correto no cabeçalho (bytes 10-11)
        cabecalho = cabecalho[:10] + struct.pack('!H', checksum) + cabecalho[12:]
        
        # Monta o datagrama completo
        datagrama = cabecalho + segmento
        
        self.enlace.enviar(datagrama, next_hop)
