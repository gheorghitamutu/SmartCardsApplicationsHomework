from Crypto.PublicKey import RSA

from config import get_config_json, get_logger


def generate_certificates():
    config = get_config_json()
    logger = get_logger()

    mpvk = RSA.generate(2048)
    with open(config['merchant_private_key'], 'w') as f_mpvk:
        f_mpvk.write(mpvk.exportKey('PEM').decode('UTF-8'))
        logger.debug("Created {}".format(config['merchant_private_key']))

    with open(config['merchant_public_key'], 'w') as f_mpbk:
        mpbk = mpvk.publickey().exportKey('PEM').decode('UTF-8')
        f_mpbk.write(mpbk)
        logger.debug("Created {}".format(config['merchant_public_key']))

    pgpvk = RSA.generate(2048)
    with open(config['payment_gateway_private_key'], 'w') as f_pgpvk:
        f_pgpvk.write(pgpvk.exportKey('PEM').decode('UTF-8'))
        logger.debug("Created {}".format(config['payment_gateway_private_key']))

    with open(config['payment_gateway_public_key'], 'w') as f_pgpbk:
        pgpbk = pgpvk.publickey().exportKey('PEM').decode('UTF-8')
        f_pgpbk.write(pgpbk)
        logger.debug("Created {}".format(config['payment_gateway_public_key']))


if __name__ == "__main__":
    generate_certificates()
