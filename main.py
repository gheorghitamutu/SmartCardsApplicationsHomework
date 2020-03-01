import os
import subprocess

import win32api

import config

if __name__ == "__main__":
    config.generate_certificates()

    module_directory = os.path.dirname(os.path.realpath(__file__))
    python_venv_path = os.path.join(module_directory, r'venv\Scripts\python.exe')
    pg_process = subprocess.Popen([python_venv_path, r'actors\payment_gateway.py'], shell=False)
    mt_process = subprocess.Popen([python_venv_path, r'actors\merchant.py'], shell=False)
    ct_process = subprocess.Popen([python_venv_path, r'actors\client.py'], shell=False)

    ct_process.wait()

    # not the greatest of ideas but it works
    win32api.TerminateProcess(int(mt_process._handle), -1)
    win32api.TerminateProcess(int(pg_process._handle), -1)
