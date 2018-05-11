import pickle
import socket
import time
import os
import sys
from DNS_Packet import *


CACHE = dict()


def save_cache():
    global CACHE
    with open('cache.che', 'wb') as output:
        pickle.dump(CACHE, output, 2)


def build_cache():
    global CACHE
    file = 'cache.che'
    if os.access(file, os.F_OK):
        print('Starting with NOT empty cache')
        with open(file, 'rb') as input:
            CACHE = pickle.load(input)
    else:
        print('Starting with empty cache')
        CACHE.clear()  # todo delete


def add_records_to_cache(packet: DNSPacket):
    def get_answers(answers):
        [add_record(ans) for ans in answers]

    def add_record(r):
        if r.atype not in {1, 2}: return
        key = (r.aname, r.atype)
        if key in CACHE:
            CACHE[key].add(CacheUnit(r, time.time(), r.ttl))
        else:
            CACHE[key] = {CacheUnit(r, time.time(), r.ttl)}

    get_answers(packet.answer)
    get_answers(packet.additional)
    get_answers(packet.authority)


class CacheUnit:
    def __init__(self, answer: Answer, time, ttl):
        self.rr = answer  # answer object
        self.time = time
        self.packet_ttl = ttl

    def __str__(self):
        return f'data: {self.rr}\ntime adding: {self.time}\nttl: {self.packet_ttl}'

    def __hash__(self):
        return hash(self.rr.aname)

    def __eq__(self, other):
        return type(other) == type(self) and self.rr == other.rr


class DNSServer():
    def __init__(self, data, addr, port, server, sock):
        self.client = addr
        self.port = port
        self.data = data
        self.server = server
        self.client_sock = sock
        self.request = read_dns_packet(self.data)

    def start(self):
        key = (self.request.question[0].qname, self.request.question[0].qtype)  # имя домена и тип запроса
        if key in CACHE:
            self.ask_cache(key, self.request.header.id)
        elif key[1] in {1, 2}:
            self.ask_server()

    def ask_server(self):
        sock_ask_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock_ask_server.settimeout(1)
        try:
            sock_ask_server.sendto(self.request.to_bytes(), (self.server, self.port))
            response = sock_ask_server.recv(1024)
            response_packet = read_dns_packet(response)
            print(f"\n{response_packet.answer[0].aname}: SERVER response")
            self.client_sock.sendto(response_packet.to_bytes(), self.client)
            add_records_to_cache(response_packet)
        except socket.error:
            print('Oops... something wrong')

    def ask_cache(self, key, id):
        reply = self.get_from_cache(key, self.request)
        if reply:
            print(f"\n{key[0]}: CACHE response")
            reply.header.set_id(id)
            add_records_to_cache(reply) # wtf
            self.client_sock.sendto(reply.to_bytes(), self.client)
        else:
            del CACHE[key]
            self.ask_server()

    def get_from_cache(self, key, packet: DNSPacket):
        data = [(p.rr.rdata, p.rr.rdlength) for p in CACHE[key] if time.time() <= p.packet_ttl + p.time]
        rdata = [d[0] for d in data]
        rd_length = data[0][1]
        for data in rdata:
            packet.answer.append(Answer(key[0], key[1], 1, 300, rd_length, data))
        packet.header.set_ancount(len(rdata))
        return packet


def main(server, port=53):
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(1/60)
        client.bind(('127.0.0.1', int(port)))
        print(f'Listening port: {port}; server: {server}')
        build_cache()
        print('Waiting for request...')
    except OSError as ex:
        print(ex)
        sys.exit()
        
    try:
        while True:
            try:
                data, addr = client.recvfrom(1024)
            except socket.timeout:
                continue
            DNSServer(data, addr, port, server, client).start()
    except KeyboardInterrupt:
        client.close()
        save_cache()
        print("\nSaving cache...")
        time.sleep(1)
        print('Closing server...')
        time.sleep(1.5)
        print('OK')
        sys.exit()
    except Exception as ex:
        client.close()
        print(ex)
        sys.exit()


if __name__ == "__main__":
    try:
        if sys.argv[1] == '127.0.0.1':
            raise ValueError("Uncorrect ip. Please enter the main dns server's ip.")
        main(*sys.argv[1:])
    except IndexError:
        main("8.8.8.8")
