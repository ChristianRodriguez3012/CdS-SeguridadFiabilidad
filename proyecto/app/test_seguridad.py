import unittest
from flask import Flask
from seguridad import app, login, logout, encrypt_data, decrypt_data, penetration_test

class TestSeguridad(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.client = self.app.test_client()
        self.client.post('/login', data={'user': 'usuario1', 'password': 'contraseña1'})

    def test_login(self):
        response = self.client.post('/login', data={'user': 'usuario1', 'password': 'contraseña1'})
        self.assertEqual(response.status_code, 200)

    def test_logout(self):
        response = self.client.get('/logout')
        self.assertEqual(response.status_code, 200)

    def test_encrypt_data(self):
        response = self.client.post('/encrypt', data={'data': 'test data'})
        self.assertEqual(response.status_code, 200)

    def test_decrypt_data(self):
        response = self.client.post('/encrypt', data={'data': 'test data'})
        encrypted_data = response.json['encrypted_data']
        key = response.json['key']
        nonce = response.json['nonce']
        response = self.client.post('/decrypt', data={'encrypted_data': encrypted_data, 'key': key, 'nonce': nonce})
        self.assertEqual(response.status_code, 200)

    def test_penetration_test(self):
        response = self.client.post('/test', data={'data': 'test data'})
        self.assertEqual(response.status_code, 200)

    def test_sql_injection(self):
        response = self.client.post('/test', data={'data': 'DROP TABLE users'})
        self.assertEqual(response.status_code, 400)

if __name__ == '__main__':
    unittest.main()