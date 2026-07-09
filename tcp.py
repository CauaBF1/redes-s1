import asyncio
import random
import threading
import time

from tcputils import *


class Servidor:
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que uma nova conexão for aceita
        """
        self.callback = callback

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, flags, window_size, checksum, urg_ptr = (
            read_header(segment)
        )

        if dst_port != self.porta:
            # Ignora segmentos que não são destinados à porta do nosso servidor
            return
        if (
            not self.rede.ignore_checksum
            and calc_checksum(segment, src_addr, dst_addr) != 0
        ):
            print("descartando segmento com checksum incorreto")
            return

        payload = segment[4 * (flags >> 12) :]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            # A flag SYN estar setada significa que é um cliente tentando estabelecer uma conexão nova
            # TODO: talvez você precise passar mais coisas para o construtor de conexão
            # [Rafa]: Realmente, precisamos passar o seq_no inicial do cliente para a conexão
            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao, seq_no)
            # TODO: você precisa fazer o handshake aceitando a conexão. Escolha se você acha melhor
            # fazer aqui mesmo ou dentro da classe Conexao.
            if self.callback:
                self.callback(conexao)
        elif id_conexao in self.conexoes:
            # Passa para a conexão adequada se ela já estiver estabelecida
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
        else:
            print(
                "%s:%d -> %s:%d (pacote associado a conexão desconhecida)"
                % (src_addr, src_port, dst_addr, dst_port)
            )


class Conexao:
    def __init__(self, servidor, id_conexao, seq_no_cliente):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.callback = None
        # Estado para saber se conexão foi fechada
        self.fechada = False
        # Lista de segmentos pendentes para retransmissão
        self.segmentos_pendentes = []
        # Segmentos criados, mas ainda aguardando espaço na janela de congestionamento
        self.segmentos_a_enviar = []
        # Timer para retransmissão de segmentos
        self.timer = None
        # Intervalo de timeout para retransmissão
        self.timeout_interval = 1
        self.estimated_rtt = None
        self.dev_rtt = None
        self.alpha = 0.125
        self.beta = 0.25
        # Guardar tempo de envio
        self.tempos_envio = {}  # seq_no -> tempo
        # Para saber se foi retransmitido
        self.retransmitidos = set()
        # Controle de congestionamento simplificado (AIMD), em unidades de MSS
        self.cwnd = 1
        # [Rafa]: aqui vou fazer o passo a passo pra inversão de papéis
        # (o que era origem no pacote que chegou, vira destino para a resposta)

        # Desempacota os dados de quem enviou (cliente) e quem recebeu (servidor)
        src_addr, src_port, dst_addr, dst_port = id_conexao

        # Primeiro: definir os números de sequência e confirmação
        self.seq_no = random.randint(
            0, 0xFFFF
        )  # Número de sequência inicial do Servidor, que adicionamos no construtor
        self.ack_no = seq_no_cliente + 1  # Confirmação do SYN do cliente

        # Segundo: Cabeçalho SYN+ACK
        # Aqui tem a inversão: porta de origem é a dst_port do pacote recebido
        flags_resposta = FLAGS_SYN | FLAGS_ACK
        cabecalho = make_header(
            dst_port, src_port, self.seq_no, self.ack_no, flags_resposta
        )

        # Terceiro: arruma o checksum
        # De novo invertemos os IPs (origem é o dst_addr, destino é o src_addr)
        segmento_resposta = fix_checksum(cabecalho, dst_addr, src_addr)

        # Quarto: envia de volta pro cliente
        self.servidor.rede.enviar(segmento_resposta, src_addr)

        # Quinto (último): como enviamos um SYN, precisamos atualizar o valor dele
        # (porque ele consome 1 bit)
        self.seq_no += 1

    # Inicia o timer para retransmissão de segmentos pendentes
    def _iniciar_timer(self):
        if self.timer is None and self.segmentos_pendentes:
            try:
                loop = asyncio.get_running_loop()
                self.timer = loop.call_later(self.timeout_interval, self._timeout)
            except RuntimeError:
                self.timer = threading.Timer(self.timeout_interval, self._timeout)
                self.timer.daemon = True
                self.timer.start()

    # Cancela o timer para retransmissão de segmentos pendentes
    def _cancelar_timer(self):
        if self.timer is not None:
            self.timer.cancel()
            self.timer = None

    # Reinicia o timer para retransmissão de segmentos pendentes
    def _reiniciar_timer(self):
        self._cancelar_timer()
        self._iniciar_timer()

    # Processa o timeout, retransmitindo o segmento pendente se necessário
    def _timeout(self):
        self.timer = None
        if self.fechada or not self.segmentos_pendentes:
            return

        self.cwnd = max(1, self.cwnd // 2)
        seq_ini, _, segmento, dest_addr = self.segmentos_pendentes[0]
        self.retransmitidos.add(seq_ini)  # Marca como retransmitido
        self.servidor.rede.enviar(segmento, dest_addr)
        self._iniciar_timer()

    def _enviar_dentro_da_janela(self):
        src_addr, _, _, _ = self.id_conexao
        while self.segmentos_a_enviar and len(self.segmentos_pendentes) < self.cwnd:
            seq_ini, seq_fim, segmento = self.segmentos_a_enviar.pop(0)
            self.servidor.rede.enviar(segmento, src_addr)
            self.tempos_envio[seq_ini] = time.time()
            self.segmentos_pendentes.append((seq_ini, seq_fim, segmento, src_addr))
            self._iniciar_timer()

    # Processa o ACK recebido, removendo segmentos pendentes se necessário
    def _processar_ack(self, ack_no):
        removeu_segmento = False
        while self.segmentos_pendentes and ack_no >= self.segmentos_pendentes[0][1]:
            seq_ini, seq_fim, segmento, dest_addr = self.segmentos_pendentes.pop(0)
            removeu_segmento = True
            
            # Só calcular RTT se não foi retransmitido
            if seq_ini not in self.retransmitidos:
                if seq_ini in self.tempos_envio:
                    sample_rtt = time.time() - self.tempos_envio[seq_ini]
                    self._atualizar_rtt(sample_rtt)
                if seq_ini in self.tempos_envio:
                    del self.tempos_envio[seq_ini]
            else:
                self.retransmitidos.discard(seq_ini)
                if seq_ini in self.tempos_envio:
                    del self.tempos_envio[seq_ini]

        if removeu_segmento:
            self.cwnd += 1
            self._reiniciar_timer()
            self._enviar_dentro_da_janela()

    # Atualiza EstimatedRTT, DevRTT e TimeoutInterval de acordo com RFC 2988
    def _atualizar_rtt(self, sample_rtt):
        if self.estimated_rtt is None:
            # Primeira medição: inicializar conforme RFC 2988
            self.estimated_rtt = sample_rtt
            self.dev_rtt = sample_rtt / 2
            self.timeout_interval = max(0.2, self.estimated_rtt + 4 * self.dev_rtt)
        else:
            # Atualizações subsequentes: usar as equações dos slides 62 e 63
            self.dev_rtt = (1 - self.beta) * self.dev_rtt + self.beta * abs(sample_rtt - self.estimated_rtt)
            self.estimated_rtt = (1 - self.alpha) * self.estimated_rtt + self.alpha * sample_rtt
            self.timeout_interval = max(0.2, self.estimated_rtt + 4 * self.dev_rtt)

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        # Verifica se a conexão foi fechada
        if self.fechada:
            return

        # Verifica se o segmento está em ordem e não é duplicado
        if seq_no != self.ack_no:
            return  # Descarta se estiver fora de ordem ou duplicado

        src_addr, src_port, dst_addr, dst_port = self.id_conexao
        # Caso o segmento seja um ACK, processa o ACK recebido
        self._processar_ack(ack_no)

        # Se o segmento tem o flag FIN, envia ACK e fecha a conexão
        if (flags & FLAGS_FIN) == FLAGS_FIN:
            self.ack_no += 1

            # Chama o callback com payload vazio, indicando que a conexão está fechada
            if self.callback:
                self.callback(self, b"")
            # Envia ACK para confirmar o recebimento do FIN
            cabecalho = make_header(
                dst_port, src_port, self.seq_no, self.ack_no, FLAGS_ACK
            )
            # Corrige o checksum e envia o segmento
            segmento = fix_checksum(cabecalho, dst_addr, src_addr)
            self.servidor.rede.enviar(segmento, src_addr)
            return

        # Se tiver payload, repassa para a camada de aplicação e atualiza o ack
        if len(payload) > 0:
            self.ack_no += len(payload)
            if self.callback:
                self.callback(self, payload)

            # Envia ACK de confirmação
            cabecalho = make_header(
                dst_port, src_port, self.seq_no, self.ack_no, FLAGS_ACK
            )
            segmento = fix_checksum(cabecalho, dst_addr, src_addr)
            self.servidor.rede.enviar(segmento, src_addr)

    # Os métodos abaixo fazem parte da API

    def registrar_recebedor(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que dados forem corretamente recebidos
        """
        self.callback = callback

    def enviar(self, dados):
        """
        Usado pela camada de aplicação para enviar dados
        """
        if len(dados) == 0:
            return

        src_addr, src_port, dst_addr, dst_port = self.id_conexao
        # Percorre os dados em blocos de tamanho máximo MSS.
        # Cada bloco vira um segmento TCP separado.
        for i in range(0, len(dados), MSS):
            payload = dados[i : i + MSS]

            # Monta o cabeçalho TCP.
            # dst_port vira a porta de origem porque agora quem está enviando é o servidor.
            # src_port vira a porta de destino porque o segmento vai para o cliente.
            # self.seq_no é o número de sequência do próximo byte enviado pelo servidor.
            # self.ack_no é o próximo byte que o servidor espera receber do cliente.
            # FLAGS_ACK mantém a flag ACK ligada
            cabecalho = make_header(
                dst_port, src_port, self.seq_no, self.ack_no, FLAGS_ACK
            )
            # Junta o cabeçalho com os dados do segmento
            segmento = fix_checksum(cabecalho + payload, dst_addr, src_addr)
            # Guarda o segmento até haver espaço na janela de congestionamento.
            self.segmentos_a_enviar.append(
                (self.seq_no, self.seq_no + len(payload), segmento)
            )

            # Atualiza o número de sequência do servidor.
            self.seq_no += len(payload)

        self._enviar_dentro_da_janela()

    def fechar(self):
        """
        Usado pela camada de aplicação para fechar a conexão
        """
        # Se a conexão já foi fechada, não faz nada
        if self.fechada:
            return

        # Envia um segmento com a flag FIN e ACK para fechar a conexão
        src_addr, src_port, dst_addr, dst_port = self.id_conexao

        # Monta o cabeçalho com a flag FIN e ACK
        cabecalho = make_header(
            dst_port, src_port, self.seq_no, self.ack_no, FLAGS_FIN | FLAGS_ACK
        )

        # Corrige o checksum e envia o segmento
        segmento = fix_checksum(cabecalho, dst_addr, src_addr)
        self.servidor.rede.enviar(segmento, src_addr)

        # Atualiza o número de sequência do servidor e marca a conexão como fechada
        self.seq_no += 1
        self.fechada = True
