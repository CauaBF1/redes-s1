#!/usr/bin/env python3
import asyncio
import re

from camadafisica import ZyboSerialDriver
from tcp import Servidor        # copie o arquivo do T2
from ip import IP               # copie o arquivo do T3
from slip import CamadaEnlace   # copie o arquivo do T4


## Implementacao da camada de aplicacao: servidor IRC da pratica 1


def validar_nome(nome):
    return re.match(rb"^[a-zA-Z][a-zA-Z0-9_-]*$", nome) is not None


def validar_canal(nome):
    return nome.startswith(b'#') and validar_nome(nome[1:])


def sair(conexao):
    print(conexao, "conexao fechada")
    if conexao.nick != b"*":
        destinatarios = set()
        for chave in conexao.canais:
            if chave in canais:
                for conn in canais[chave]:
                    if conn != conexao:
                        destinatarios.add(conn)

        msg = b":" + conexao.nick + b" QUIT :Connection closed\r\n"
        for conn in destinatarios:
            try:
                conn.enviar(msg)
            except Exception:
                pass

        apelidos_em_uso.pop(conexao.nick.lower(), None)

        for chave in conexao.canais.copy():
            if chave in canais:
                canais[chave].discard(conexao)
                if not canais[chave]:
                    del canais[chave]
        conexao.canais.clear()

    conexao.fechar()


def tratar_mensagens(conexao, linha):
    if linha.startswith(b"PING "):
        payload = linha.split(b" ", 1)[1]
        conexao.enviar(b":server PONG server :" + payload + b"\r\n")

    elif linha.startswith(b"NICK "):
        nome = linha.split(b" ", 1)[1]

        if not validar_nome(nome):
            conexao.enviar(
                b":server 432 "
                + conexao.nick
                + b" "
                + nome
                + b" :Erroneous nickname\r\n"
            )
            return

        chave = nome.lower()
        if chave in apelidos_em_uso and apelidos_em_uso[chave] is not conexao:
            conexao.enviar(
                b":server 433 "
                + conexao.nick
                + b" "
                + nome
                + b" :Nickname is already in use\r\n"
            )
            return

        nick_antigo = conexao.nick
        if nick_antigo != b"*":
            apelidos_em_uso.pop(nick_antigo.lower(), None)

        conexao.nick = nome
        apelidos_em_uso[chave] = conexao

        if nick_antigo == b"*":
            conexao.enviar(b":server 001 " + conexao.nick + b" :Welcome\r\n")
            conexao.enviar(
                b":server 422 " + conexao.nick + b" :MOTD File is missing\r\n"
            )
        else:
            conexao.enviar(b":" + nick_antigo + b" NICK " + conexao.nick + b"\r\n")

    elif linha.startswith(b"PRIVMSG "):
        parts = linha.split(b" ", 2)
        if len(parts) != 3 or not parts[2].startswith(b":"):
            return

        destinatario = parts[1]
        conteudo = parts[2][1:]

        if destinatario.startswith(b"#"):
            chave = destinatario.lower()
            if chave in canais:
                msg = (
                    b":"
                    + conexao.nick
                    + b" PRIVMSG "
                    + destinatario
                    + b" :"
                    + conteudo
                    + b"\r\n"
                )
                for conn in canais[chave]:
                    if conn != conexao:
                        conn.enviar(msg)
        else:
            chave = destinatario.lower()
            if chave in apelidos_em_uso:
                dest_conexao = apelidos_em_uso[chave]
                msg = (
                    b":"
                    + conexao.nick
                    + b" PRIVMSG "
                    + destinatario
                    + b" :"
                    + conteudo
                    + b"\r\n"
                )
                dest_conexao.enviar(msg)

    elif linha.startswith(b"JOIN "):
        canal = linha.split(b" ", 1)[1]

        if not validar_canal(canal):
            conexao.enviar(b":server 403 " + canal + b" :No such channel\r\n")
            return

        chave = canal.lower()
        if chave not in canais:
            canais[chave] = set()

        canais[chave].add(conexao)
        conexao.canais.add(chave)

        msg = b":" + conexao.nick + b" JOIN :" + canal + b"\r\n"
        for conn in canais[chave]:
            conn.enviar(msg)

        lista_nicks = b" ".join(sorted(conn.nick for conn in canais[chave]))
        conexao.enviar(
            b":server 353 "
            + conexao.nick
            + b" = "
            + canal
            + b" :"
            + lista_nicks
            + b"\r\n"
        )
        conexao.enviar(
            b":server 366 "
            + conexao.nick
            + b" "
            + canal
            + b" :End of /NAMES list.\r\n"
        )

    elif linha.startswith(b"PART "):
        canal = linha.split(b" ", 1)[1].split(b" ", 1)[0]
        chave = canal.lower()
        if chave in canais and conexao in canais[chave]:
            msg = b":" + conexao.nick + b" PART " + canal + b"\r\n"
            for conn in canais[chave]:
                conn.enviar(msg)
            canais[chave].remove(conexao)
            conexao.canais.remove(chave)
            if not canais[chave]:
                del canais[chave]


def dados_recebidos(conexao, dados):
    if dados == b"":
        sair(conexao)
        return

    conexao.dados_residuais += dados

    while b"\r\n" in conexao.dados_residuais:
        linha, conexao.dados_residuais = conexao.dados_residuais.split(b"\r\n", 1)
        tratar_mensagens(conexao, linha)


def conexao_aceita(conexao):
    print(conexao, "nova conexao")
    conexao.nick = b"*"
    conexao.dados_residuais = b""
    conexao.canais = set()
    conexao.registrar_recebedor(dados_recebidos)


apelidos_em_uso = {}
canais = {}


## Integracao com as demais camadas

nossa_ponta = '192.168.200.4'
outra_ponta = '192.168.200.3'
porta_tcp = 6667

driver = ZyboSerialDriver()
linha_serial = driver.obter_porta(0)

enlace = CamadaEnlace({outra_ponta: linha_serial})
rede = IP(enlace)
rede.definir_endereco_host(nossa_ponta)
rede.definir_tabela_encaminhamento([
    ('0.0.0.0/0', outra_ponta)
])
servidor = Servidor(rede, porta_tcp)
servidor.registrar_monitor_de_conexoes_aceitas(conexao_aceita)
print('Servidor IRC escutando em {}:{}.'.format(nossa_ponta, porta_tcp))
asyncio.get_event_loop().run_forever()
