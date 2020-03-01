import pickle
import socket

from config.config_helper import get_config_json, get_logger
from crypto_utils.crypto_helper import encrypt_rsa_aes, decrypt_rsa_aes, verify_signature, sign


class PaymentGateway:
    def __init__(self):
        self.config = get_config_json()
        self.logger = get_logger()
        self.address = self.config['payment_gateway_address']
        self.port = self.config['payment_gateway_port']
        self.private_key = self.config['payment_gateway_private_key']
        self.pg_data = self.config['payment_gateways'][0]
        self.password = self.config['payment_gateway_aes_password']

    def keep_making_transactions(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((self.address, self.port))
        s.listen(1)

        code = ''
        sid = ''
        amount = ''
        nonce = ''

        while True:
            connection, _ = s.accept()
            data = connection.recv(4096)
            message, password = pickle.loads(data)
            decrypted_message = decrypt_rsa_aes(message, password, self.private_key)
            if len(decrypted_message.split(',')) == 3:  # merchant
                code, sid, amount, nonce = self.exchange_sub_protocol(connection, decrypted_message)
            else:  # client
                self.resolution_sub_protocol(connection, decrypted_message, code, sid, amount, nonce)

            connection.close()

    def exchange_sub_protocol(self, connection, decrypted_message):
        payment_message, password, amount_signature = tuple(decrypted_message.split(','))
        decrypted_payment_message = decrypt_rsa_aes(
            bytes.fromhex(payment_message),
            bytes.fromhex(password),
            self.private_key)
        card_number, expiration_date, code, sid, amount, client_pubkey, nonce, client_signature = \
            tuple(decrypted_payment_message.split(","))
        self.logger.debug('STEP 4: {} received data from merchant!'.format(sid))
        amount_validation = verify_signature(
            '{},{},{}'.format(sid, client_pubkey, amount).encode('UTF-8'),
            bytes.fromhex(amount_signature),
            self.config['merchant_public_key'])
        self.logger.debug('STEP 4: {} Sid and clientPubK and amount are valid {}'.format(sid, amount_validation))
        client_data = '{},{},{},{},{},{},{}'.format(
            card_number,
            expiration_date,
            code,
            sid,
            amount,
            client_pubkey,
            nonce
        )
        client_data_validation = verify_signature(
            client_data.encode('UTF-8'),
            bytes.fromhex(client_signature),
            client_pubkey)
        self.logger.debug('STEP 4: {} client personal data is valid {}'.format(sid, client_data_validation))

        if (card_number, expiration_date, code) != (
                self.pg_data['card_number'],
                self.pg_data['card_expiration_date'],
                self.pg_data['code']) or int(amount) < 0:
            response_code = 1
        elif int(amount) > int(self.pg_data['amount']):
            response_code = 2
        else:
            response_code = 3
        self.logger.debug('STEP 4: {} {}'.format(sid, self.config['payment_gateway_response_code'][str(response_code)]))
        response_signature = sign(
            '{},{},{},{}'.format(response_code, sid, amount, nonce).encode('UTF-8'), self.private_key)
        encrypted_message = encrypt_rsa_aes(
            '{},{},{},{},{}'.format(response_code, sid, amount, nonce, response_signature.hex()),
            self.password,
            self.config['merchant_public_key'])
        serialized_encrypted_message = pickle.dumps(encrypted_message)
        connection.send(serialized_encrypted_message)
        self.logger.debug('STEP 5: {} sent data to merchant!'.format(sid))
        return response_code, sid, amount, nonce

    def resolution_sub_protocol(self, connection, decrypted_message, exchange_return_code, sid, amount, nonce):
        self.logger.debug('STEP 7: Resolution sub-protocol initiated!')
        self.logger.debug('STEP 7: Received message from client')
        client_sid, client_amount, client_nonce, client_pubkey, signature = tuple(decrypted_message.split(','))
        validation = verify_signature(
            '{},{},{},{}'.format(client_sid, client_amount, client_nonce, client_pubkey).encode('UTF-8'),
            signature,
            bytes.fromhex(client_pubkey))
        self.logger.debug('STEP 7: {} Sid, amount, nonce and client public key are valid: {}'.format(sid, validation))
        resolution_response = 0
        if (client_sid, client_amount, client_nonce) == (sid, amount, nonce):
            self.logger.debug('STEP 7: This transaction exists!')
            resolution_response = exchange_return_code
        else:
            self.logger.debug('STEP 7: This transaction has not reached PG!')
        response_message = '{}, {}'.format(resolution_response, sid)
        response_message_signature = sign(response_message.encode("UTF-8"), self.private_key)
        encrypted_response_message = encrypt_rsa_aes(
            '{},{}'.format(response_message, response_message_signature.hex()),
            self.password,
            bytes.fromhex(client_pubkey))
        serialized_encrypted_response_message = pickle.dumps(encrypted_response_message)
        connection.send(serialized_encrypted_response_message)
        self.logger.debug('STEP 8: Sent message to client!')


if __name__ == "__main__":
    pg = PaymentGateway()
    pg.keep_making_transactions()
