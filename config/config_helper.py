import json
import logging
import os
import sys


def get_config_json():
    module_directory = os.path.dirname(os.path.realpath(__file__))
    config_abs_path = os.path.join(module_directory, r'config')
    with open(config_abs_path, 'r') as fc:
        config = json.load(fc)

        # modify paths for files relative to this one
        config['merchant_public_key'] = os.path.join(module_directory, config['merchant_public_key'])
        config['merchant_private_key'] = os.path.join(module_directory, config['merchant_private_key'])
        config['payment_gateway_public_key'] = os.path.join(module_directory, config['payment_gateway_public_key'])
        config['payment_gateway_private_key'] = os.path.join(module_directory, config['payment_gateway_private_key'])
        config['log_file'] = os.path.join(module_directory, config['log_file'])

        return config


def get_logger():
    logger = logging.getLogger()
    if len(logger.handlers) > 0:  # already initialized
        return logger

    try:
        config = get_config_json()
    except FileNotFoundError as e:
        print(e)
        sys.exit()

    dir_log_file = os.path.dirname(config['log_file'])
    if not os.path.exists(dir_log_file) and dir_log_file != '':  # ensure subdirs for log file creation
        os.makedirs(os.path.dirname(config['log_file']))

    logging.basicConfig(
        filename='{}'.format(config['log_file']),
        format='%(asctime)s.%(msecs)03d %(process)6d %(funcName)20s %(lineno)4i: %(levelname)8s %(message)s')

    logger.setLevel(logging.DEBUG)
    logging.getLogger().addHandler(logging.StreamHandler())

    return logger
