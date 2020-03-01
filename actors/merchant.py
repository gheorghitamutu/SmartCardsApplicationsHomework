import pickle
import random
import socket

from config.config_helper import get_config_json, get_logger
from crypto_utils.crypto_helper import encrypt_rsa_aes, decrypt_rsa_aes, verify_signature, sign


class Merchant:
    def __init__(self):
        self.config = get_config_json()
        self.logger = get_logger()
        self.address = self.config['merchant_address']
        self.port = self.config['merchant_port']
        self.password = self.config['merchant_aes_password']
        self.private_key = self.config['merchant_private_key']

    def keep_selling(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((self.address, self.port))
        s.listen(1)

        while True:
            connection, _ = s.accept()
            sid, client_pubkey = self.confirm_identity(connection)
            self.sell(connection, client_pubkey, sid)
            connection.close()

    def confirm_identity(self, connection):
        message = connection.recv(4096)
        self.logger.debug("STEP 1: Received data from client!")
        key, password = pickle.loads(message)
        decrypted_key = decrypt_rsa_aes(key, password, self.config['merchant_private_key'])
        sid = self.get_sid()
        sid_signature = sign(str(sid).encode('UTF-8'), self.config['merchant_private_key'])
        message = '{},{}'.format(
            sid,
            sid_signature.hex()
        )
        sid_message = encrypt_rsa_aes(message, self.config['merchant_aes_password'], decrypted_key)
        serialized_sid_message = pickle.dumps(sid_message)
        connection.send(serialized_sid_message)
        self.logger.debug("STEP 2: Sending data to client!")
        return sid, decrypted_key

    def sell(self, client_connection, client_pubkey, sid):
        message = client_connection.recv(4096)
        self.logger.debug("STEP 3: Received data from client!")
        payment, password = pickle.loads(message)
        decrypted_packet = decrypt_rsa_aes(payment, password, self.config['merchant_private_key'])
        payment_message, decrypted_password, order_desc, from_sid, amount, signature = decrypted_packet.split(",")
        validation = verify_signature(
            '{},{},{}'.format(order_desc, sid, amount).encode('UTF-8'),
            bytes.fromhex(signature),
            client_pubkey)
        self.logger.debug('STEP 3: Payment order is valid: {}'.format(validation))
        self.logger.debug('STEP 3: Sid is valid: {}'.format(sid == int(from_sid)))
        if self.config['resolutions']['error_step_4']:
            self.logger.debug('STEP 4: {} Error occurred!'.format(sid))
            return

        connection_gp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection_gp.connect((self.config['payment_gateway_address'], self.config['payment_gateway_port']))
        signature = sign(
            '{},{},{}'.format(from_sid, client_pubkey, amount).encode("UTF-8"),
            self.config['merchant_private_key'])
        message_gp = '{},{},{}'.format(payment_message, decrypted_password, signature.hex())
        encrypted_message_gp = encrypt_rsa_aes(message_gp, self.password, self.config['payment_gateway_public_key'])
        serialized_encrypted_message_gp = pickle.dumps(encrypted_message_gp)
        connection_gp.send(serialized_encrypted_message_gp)
        self.logger.debug('STEP 4: {} sent data to PG!'.format(sid))
        response = connection_gp.recv(4096)
        self.logger.debug('STEP 5: {} received data to PG!'.format(sid))
        response_message, password = pickle.loads(response)
        decrypted_response_message = decrypt_rsa_aes(response_message, password, self.private_key)
        pg_code, pg_sid, pg_amount, pg_nonce, pg_signature = tuple(decrypted_response_message.split(','))
        validation = verify_signature(
            '{},{},{}'.format(pg_code, pg_sid, pg_amount, pg_nonce).encode('UTF-8'),
            bytes.fromhex(pg_signature),
            self.config['payment_gateway_public_key'])
        self.logger.debug('STEP 5: {} Response code, sid, amount and nonce are valid: {}'.format(sid, validation))
        self.logger.debug('STEP 8: {} {}'.format(sid, self.config['payment_gateway_response_code'][str(pg_code)]))
        if self.config['resolutions']['error_step_6']:
            self.logger.debug('STEP 6: {} Error occurred!'.format(sid))
            return

        encrypted_client_response = encrypt_rsa_aes(decrypted_response_message, self.password, client_pubkey)
        serialized_client_response = pickle.dumps(encrypted_client_response)
        client_connection.send(serialized_client_response)
        self.logger.debug('STEP 6: Sid {} sent data to client!'.format(sid))

    @staticmethod
    def get_sid():
        return random.randint(0, 10000)


if __name__ == "__main__":
    merchant = Merchant()
    merchant.keep_selling()
