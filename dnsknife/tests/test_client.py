from __future__ import absolute_import

import socket
import unittest

import dns.message
import dns.name
import dns.rdatatype
import dns.resolver
import dns.rrset

import mock

import dnsknife


class TestClient(unittest.TestCase):

    def setUp(self):
        pass

    def getaddrinfo(*args):
        return [(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP,
                '', ('1.2.3.4', 53))]

    def reply(self, q, where, timeout=None, port=53, af=None,
              source=None, source_port=0, ignore_unexpected=False,
              one_rr_per_rrset=False):
        exvals = {
            dns.rdatatype.NS: ['ns1.', 'ns2.'],
            dns.rdatatype.A: ['1.2.3.4'],
        }

        rrset = dns.rrset.from_text_list(q.question[0].name, 300, 'IN',
                                         q.question[0].rdtype,
                                         exvals[q.question[0].rdtype])
        response = dns.message.make_response(q)
        response.answer.append(rrset)
        response.index = None
        return response

    def test_socks_not_used_for_NS(self):
        dnsknife.set_socks5_server('localhost')
        with mock.patch('socks.socksocket') as mock_socks, \
            mock.patch('dns.query.udp', side_effect=self.reply) as mock_udp, \
            mock.patch('dns.query.tcp', side_effect=self.reply) as mock_tcp, \
            mock.patch('socket.getaddrinfo', side_effect=self.getaddrinfo) \
                as mock_socket:
            dnsknife.query('example.com', dns.rdatatype.A)
            self.assertEqual(mock_socket.call_count, 0)
            self.assertEqual(mock_socks.call_count, 0)
            self.assertEqual(mock_tcp.call_count, 0)
            self.assertEqual(mock_udp.call_count, 1)

    def test_ns_called(self):
        c = dnsknife.Checker('test.com')
        with mock.patch('socks.socksocket'), \
                mock.patch('dns.query.udp', side_effect=self.reply) \
                as mock_udp, \
                mock.patch('dns.query.tcp', side_effect=self.reply) \
                as mock_tcp, \
                mock.patch('socket.getaddrinfo', side_effect=self.getaddrinfo)\
                as mock_socket:
            c.query_at('test.com', 'NS', '1.2.3.4')
            self.assertEqual(mock_udp.call_args[0][1], '1.2.3.4')
            self.assertEqual(mock_tcp.call_count, 0)
            self.assertEqual(mock_socket.call_count, 1)

    def test_socks_used_for_direct(self):
        dnsknife.set_socks5_server('localhost')
        c = dnsknife.Checker('test.com', direct=True)
        with mock.patch('socks.socksocket') as mock_socks, \
            mock.patch('socket.getaddrinfo', side_effect=self.getaddrinfo) \
                as mock_socket:
                    try:
                        c.query_at('test.com', 'A', '1.2.3.4')
                    except:
                        # Socket None, will fail. But test is about socks
                        pass
                    self.assertEqual(mock_socket.call_count, 1)
                    self.assertEqual(mock_socks.call_count, 1)
