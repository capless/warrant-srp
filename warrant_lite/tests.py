import unittest

from envs import env

from warrant_lite import WarrantLite, TokenVerificationException


class WarrantLiteTestCase(unittest.TestCase):

    def setUp(self):
        if env('USE_CLIENT_SECRET') == 'True':
            self.client_secret = env('COGNITO_CLIENT_SECRET')
            self.app_id = env('COGNITO_APP_ID')
        else:
            self.app_id = env('COGNITO_APP_ID')
            self.client_secret = None
        self.cognito_user_pool_id = env('COGNITO_USER_POOL_ID')
        self.username = env('COGNITO_TEST_USERNAME')
        self.password = env('COGNITO_TEST_PASSWORD')
        self.wl = WarrantLite(username=self.username, password=self.password,
                          pool_id=self.cognito_user_pool_id,
                          client_id=self.app_id, client_secret=self.client_secret)

    def tearDown(self):
        del self.wl

    def test_verify_token(self):
        tokens = self.wl.authenticate_user()

        bad_access_token = '{}wrong'.format(
            tokens['AuthenticationResult']['AccessToken'])

        with self.assertRaises(TokenVerificationException) as vm:
            self.wl.verify_token(bad_access_token, 'access_token', 'access')

    def test_authenticate_user(self):
        tokens = self.wl.authenticate_user()
        self.assertTrue('IdToken' in tokens['AuthenticationResult'])
        self.assertTrue('AccessToken' in tokens['AuthenticationResult'])
        self.assertTrue('RefreshToken' in tokens['AuthenticationResult'])


if __name__ == '__main__':
    unittest.main()