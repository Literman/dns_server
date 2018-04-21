import bitstring
import functools


class DNSPacket:
    def __init__(self, header, question, answer, authority, additional):
        self.header = header
        self.question = question
        self.answer = answer
        self.authority = authority
        self.additional = additional

    def to_bytes(self):
        return self.header + (self.question + self.answer + self.authority + self.additional)


class Header:
    def __init__(self, id, qr=0, opcode=0, authoritative=0, truncated=0, recursion_desired=0,
                 recursion_available=0, reply_code=0, questions=0, answer_rrs=0, authority_rrs=0, additional_rrs=0):
        self.id = id  # Идентификация
        self.qr = qr  # Тип сообщения: 0 - запрос, 1 - ответ
        self.opcode = opcode  # Код операции: 0 - стандарт, 1 - инверсный, 2 - статус сервера
        self.aa = authoritative  # Авторитетный ответ
        self.tc = truncated  # Обрезано
        self.rd = recursion_desired  # Требуется рукурсия
        self.ra = recursion_available  # Рекурсия возможна
        self.rcode = reply_code  # Код возврата: 3 - имени домена не существует
        self.qdcount = questions  # Количество вопросов
        self.ancount = answer_rrs  # Количество обычных ответов
        self.nscount = authority_rrs  # Полномочный источник
        self.arcount = additional_rrs  # Дополнительная информация

    def to_bytes(self):
        bits_packet = bitstring.BitArray(length=96)
        bits_packet[0:16] = bitstring.pack('uint: 16', self.id)
        bits_packet[16:17] = bitstring.pack('uint: 1', self.qr)
        bits_packet[17:21] = bitstring.pack('uint: 4', self.opcode)
        bits_packet[21:22] = bitstring.pack('uint: 1', self.aa)
        bits_packet[22:23] = bitstring.pack('uint: 1', self.tc)
        bits_packet[23:24] = bitstring.pack('uint: 1', self.rd)
        bits_packet[24:25] = bitstring.pack('uint: 1', self.ra)
        bits_packet[28:32] = bitstring.pack('uint: 4', self.rcode)
        bits_packet[32:48] = bitstring.pack('uint: 16', self.qdcount)
        bits_packet[48:64] = bitstring.pack('uint: 16', self.ancount)
        bits_packet[64:80] = bitstring.pack('uint: 16', self.nscount)
        bits_packet[80:96] = bitstring.pack('uint: 16', self.arcount)
        return bits_packet.tobytes()

    def __add__(self, other):
        return functools.reduce(lambda a, b: a + b.to_bytes(), other, self.to_bytes())

    def set_id(self, id):
        self.id = id

    def set_ancount(self, n):
        self.ancount = n


class Question:
    def __init__(self, qname, qtype, qclass):
        self.qname = qname  # Доменное имя
        self.qtype = qtype  # Тип запроса: 1-А, 2-NS, 5-СNAME, 6-SOA, 12-PTR, 28-AAAA
        self.qclass = qclass  # Класс запроса

    def to_bytes(self):
        bytes_name = name_to_bytes(self.qname)[0]
        bits_packet = bitstring.BitArray(length=32)
        bits_packet[0:16] = bitstring.pack('uint: 16', self.qtype)
        bits_packet[16:32] = bitstring.pack('uint: 16', self.qclass)
        return bytes_name + bits_packet.tobytes()


class Answer:
    def __init__(self, aname, atype, aclass, ttl, data_length, address):
        self.aname = aname  # Доменное имя
        self.atype = atype  # Тип запроса
        self.aclass = aclass  # Класс запроса
        self.ttl = ttl  # Время жизни записи в кеше
        self.rdlength = data_length  # Размер данных
        self.rdata = address  # Адресс

    def to_bytes(self):
        bytes_name = name_to_bytes(self.aname)[0]
        bits_packet = bitstring.BitArray()
        bits_packet[0:16] = bitstring.pack('uint: 16', self.atype)
        bits_packet[16:32] = bitstring.pack('uint: 16', self.aclass)
        bits_packet[32:64] = bitstring.pack('uint: 32', self.ttl)
        if self.atype == 1:
            address = address_to_bytes(self.rdata)
            bits_packet[64:86] = bitstring.pack('uint: 16', self.rdlength)
        else:
            address, length = name_to_bytes(self.rdata)
            bits_packet[64:86] = bitstring.pack('uint: 16', length)
        return bytes_name + bits_packet.tobytes() + address

    def __str__(self):
        return '\n'.join((
                    f'Name: {self.aname}',
                    f'Type: ({self.atype})',
                    f'Class: IN ({self.aclass})',
                    f'Time to live: {self.ttl}',
                    f'Data length: {self.rdlength}',
                    f'Address: {self.rdata}'))

    def __eq__(self, other):
        return (self.aname == other.aname and self.atype == other.atype and
                self.aclass == other.aclass and self.ttl == other.ttl and
                self.rdlength == other.rdlength and self.rdata == other.rdata)


def read_head(bit_packet: bitstring.Bits):
    id = bit_packet[0:16].uint
    qr = bit_packet[16:17].uint
    opcode = bit_packet[17:21].uint
    aa = bit_packet[21:22].uint
    tc = bit_packet[22:23].uint
    rd = bit_packet[23:24].uint
    ra = bit_packet[24:25].uint
    rcode = bit_packet[28:32].uint
    qcount = bit_packet[32:48].uint
    ancount = bit_packet[48:64].uint
    nscount = bit_packet[64:80].uint
    arcount = bit_packet[80:96].uint
    return Header(id, qr, opcode, aa, tc, rd, ra, rcode, qcount, ancount, nscount, arcount)


def read_questions(bit_packet: bitstring.Bits, header: Header):
    questions = []
    index = 96
    for i in range(header.qdcount):
        question, index = read_question(bit_packet, index)
        questions.append(question)
    return questions, index


def read_question(bit_packet: bitstring.Bits, index):
    qname, off = read_name(bit_packet, index, name='')
    qtype = bit_packet[off:off+16].uint
    qclass = bit_packet[off+16:off+32].uint
    return Question(qname, qtype, qclass), off + 32


def read_answers(bit_packet: bitstring.Bits, header: Header, index):
    def get_answers(count, index):
        answers = []
        for i in range(count):
            answer, index = read_answer(bit_packet, index)
            answers.append(answer)
        return answers, index

    answers_rrs, index = get_answers(header.ancount, index)
    authority_rrs, index = get_answers(header.nscount, index)
    additional_rrs, index = get_answers(header.arcount, index)
    return answers_rrs, authority_rrs, additional_rrs


def read_answer(bit_packet: bitstring.Bits, index):
    aname, off = read_name(bit_packet, index, name='')
    atype = bit_packet[off:off+16].uint
    aclass = bit_packet[off+16:off+32].uint
    ttl = bit_packet[off+32:off+64].uint
    data_length = bit_packet[off+64: off+80].uint
    address, end_index = read_address(bit_packet, off+80, data_length, atype)
    return Answer(aname, atype, aclass, ttl, data_length, address), end_index


def read_address(bit_packet: bitstring.Bits, index, data_length, address_type):
    if address_type == 1:
        address = ''
        for i in range(data_length):
            address += str(bit_packet[index:index+8].uint) + '.'
            index += 8
        return address[:-1], index
    elif address_type == 2:
        address, index = read_name(bit_packet, index, name='')
        return address, index


def read_name(bit_packet: bitstring.Bits, index, name):
    char_count = bit_packet[index:index+8].uint
    while char_count:
        if char_count >= 192:
            hoop_place = bit_packet[index+2:index+16].uint * 8
            name = read_name(bit_packet, hoop_place, name)[0]
            return name, index + 16
        else:
            index += 8
            for i in range(char_count):
                name += bit_packet[index:index+8].bytes.decode('ASCII')
                index += 8
            name += '.'
        char_count = bit_packet[index:index+8].uint
    else:
        return name[:-1], index + 8


def name_to_bytes(name):
    bits_name = bitstring.BitArray()
    name_length = 0
    idx = 0
    for name_part in name.split('.'):
        bits_name[idx:idx+8] = bitstring.pack('uint: 8', len(name_part))
        name_length += len(name_part) + 1
        idx += 8
        for char in name_part:
            bits_name[idx:idx+8] = bitstring.pack('hex: 8', char.encode('ASCII').hex())
            idx += 8
    bits_name[idx:idx+8] = bitstring.pack('uint: 8', 0)
    return bits_name.tobytes(), name_length + 1


def address_to_bytes(address):
    bits_address = bitstring.BitArray()
    idx = 0
    for address_part in address.split('.'):
        bits_address[idx:idx+8] = bitstring.pack('uint: 8', int(address_part))
        idx += 8
    return bits_address.tobytes()


def read_dns_packet(data):
    bit_data = bitstring.Bits(data)
    head = read_head(bit_data)
    questions, index = read_questions(bit_data, head)
    answer_rrs, authority_rrs, additional_rrs = read_answers(bit_data, head, index)
    return DNSPacket(head, questions, answer_rrs, authority_rrs, additional_rrs)
