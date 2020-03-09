# SmartCardsApplicationsHomework\venv\Lib\site-packages\pycrypto-2.6.1-py3.7-win-amd64.egg\Crypto\Random\OSRNG\nt.py
# change import winrandom to from . import winrandom
# https://stackoverflow.com/questions/24804829/no-module-named-winrandom-when-using-pycrypto

import pickle
import socket

from Crypto.PublicKey import RSA

from config.config_helper import get_config_json, get_logger
from crypto_utils.crypto_helper import encrypt_rsa_aes, decrypt_rsa_aes, verify_signature, sign


class Client:
    def __init__(self):
        self.config = get_config_json()
        self.logger = get_logger()
        self.rsa = RSA.generate(2048)
        self.rsa_private_encoded = self.rsa.export_key()
        self.rsa_pub = self.rsa.publickey()
        self.rsa_pub_encoded = self.rsa_pub.export_key()
        self.nonce = 0  # https://security.stackexchange.com/questions/3001/what-is-the-use-of-a-client-nonce
        self.transaction_data = self.config['clients'][0]
        self.password = self.config['client_aes_password']
        self.sid = None  # acquired from merchant

    def buy(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.config['client_address'], self.config['merchant_port']))
        self.confirm_identity(s)
        self.make_transaction(s)

    def confirm_identity(self, connection):
        data = encrypt_rsa_aes(self.rsa_pub_encoded.decode('UTF-8'), self.password, self.config['merchant_public_key'])
        serialized_data = pickle.dumps(data)
        connection.send(serialized_data)
        self.logger.debug('STEP 1: Sent data to merchant!')
        serialized_sid_packet = connection.recv(4096)
        self.logger.debug('STEP 2: Received data from merchant!')
        message, key = pickle.loads(serialized_sid_packet)
        self.sid, sid_signature = decrypt_rsa_aes(message, key, self.rsa_private_encoded).split(",", 1)
        verification = verify_signature(
            self.sid.encode('UTF-8'), bytes.fromhex(sid_signature), self.config['merchant_public_key'])
        self.logger.debug('STEP 2: {} is valid: {}'.format(self.sid, verification))

    def make_transaction(self, connection):
        payment_info = '{},{},{},{},{},{},{}'.format(
            self.transaction_data['card_number'],
            self.transaction_data['card_expiration_date'],
            self.transaction_data['code'],
            self.sid,
            self.transaction_data['amount'],
            self.rsa_pub_encoded.decode("UTF-8"),
            self.nonce
        )
        payment_info_signature = sign(payment_info.encode("UTF-8"), self.rsa_private_encoded)
        payment_message, key = \
            encrypt_rsa_aes(
                '{},{}'.format(payment_info, payment_info_signature.hex()),
                self.password,
                self.config['payment_gateway_public_key'])
        payment_order_info = '{},{},{}'.format(
            self.transaction_data['order'],
            self.sid,
            self.transaction_data['amount']
        )
        payment_order_signature = sign(payment_order_info.encode("UTF-8"), self.rsa_private_encoded)
        packet = '{},{},{}'.format(
            payment_message.hex(),
            key.hex(),
            '{},{}'.format(payment_order_info, payment_order_signature.hex())
        )
        encrypted_packet = encrypt_rsa_aes(packet, self.password, self.config['merchant_public_key'])
        serialized_encrypted_packet = pickle.dumps(encrypted_packet)
        connection.send(serialized_encrypted_packet)
        self.logger.debug('STEP 3: {} Sent data to merchant!'.format(self.sid))
        try:
            connection.settimeout(5)
            response = connection.recv(4096)
            self.logger.debug('STEP 6: {} Received data from merchant!'.format(self.sid))
            connection.settimeout(None)
        except Exception as e:
            self.logger.exception(e)
            self.reach_resolution(self.transaction_data['amount'])
            return

        deserialized_response, aes_key = pickle.loads(response)
        decrypted_response = decrypt_rsa_aes(deserialized_response, aes_key, self.rsa.exportKey())
        code, sid, amount, nonce, signature = tuple(decrypted_response.split(','))
        message = '{},{},{},{}'.format(code, sid, amount, nonce)
        are_valid = verify_signature(
            message.encode('UTF-8'),
            bytes.fromhex(signature),
            self.config['payment_gateway_public_key'])
        self.logger.debug('STEP 6: {} Response code, sid, amount and nonce are valid {}'.format(sid, are_valid))
        self.logger.debug('STEP 6: {} Sid and nonce are correct {}'.format(
            str(self.sid), str(self.sid) == sid and str(self.nonce) == nonce))
        self.logger.debug('STEP 6: {} {}'.format(sid, self.config['payment_gateway_response_code'][str(code)]))

    def reach_resolution(self, amount):
        self.logger.debug('STEP 7: {} Timeout occurred!'.format(self.sid))
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.config['payment_gateway_address'], self.config['payment_gateway_port']))
        message = '{},{},{},{}'.format(
            self.sid,
            amount,
            self.nonce,
            self.rsa_pub_encoded.hex()
        )
        message_signature = sign(message.encode('UTF-8'), self.rsa_pub_encoded)
        encrypted_message = \
            encrypt_rsa_aes(
                '{},{}'.format(message, message_signature.hex()),
                self.password,
                self.config['payment_gateway_public_key'])
        serialized_encrypted_message = pickle.dumps(encrypted_message)
        s.send(serialized_encrypted_message)
        self.logger.debug('STEP 7: {} Sent message to PG!'.format(self.sid))
        response = s.recv(4096)
        self.logger.debug('STEP 8: {} Received message from PG!'.format(self.sid))
        message, key = pickle.loads(response)
        decrypted_message = decrypt_rsa_aes(message, key, self.rsa_pub_encoded)
        code, sid, response_signature = tuple(decrypted_message.split(','))
        validation = \
            verify_signature(
                '{},{}'.format(code, sid).encode('UTF-8'),
                bytes.fromhex(response_signature),
                self.config['payment_gateway_public_key'])
        self.logger.debug('STEP 8: {} Response code and sid are valid {}'.format(sid, validation))
        self.logger.debug('STEP 8: {} {}'.format(sid, self.config['payment_gateway_response_code'][str(code)]))


if __name__ == "__main__":
    client = Client()
    client.buy()
