import datetime
import unittest

from envs import env

from warrant_lite import WarrantLite, TokenVerificationException, timestamp_string


class WarrantLiteTestCase(unittest.TestCase):

    def setUp(self):
        if env('USE_CLIENT_SECRET') == 'True':
            self.client_secret = env('COGNITO_CLIENT_SECRET')
            self.app_id = env('COGNITO_APP_WITH_SECRET_ID')
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

class TimestampStringTest(unittest.TestCase):

    def test_when_no_padding_is_necessary_should_return(self):
        date = datetime.datetime(2020, 10, 28, hour=16, minute=36,
                                      second=17, microsecond=14,
                                      tzinfo=datetime.timezone.utc)

        actual = timestamp_string(date)

        self.assertEqual("Wed Oct 28 16:36:17 UTC 2020", actual)

    def test_should_pad_timestamp(self):
        date = datetime.datetime(2020, 10, 28, hour=1, minute=2,
                                      second=3, microsecond=4,
                                      tzinfo=datetime.timezone.utc)

        actual = timestamp_string(date)

        self.assertEqual("Wed Oct 28 01:02:03 UTC 2020", actual)

    def test_should_not_pad_day(self):
        date = datetime.datetime(2020, 10, 2, hour=1, minute=2,
                                      second=3, microsecond=4,
                                      tzinfo=datetime.timezone.utc)

        actual = timestamp_string(date)

        self.assertEqual("Fri Oct 2 01:02:03 UTC 2020", actual)

if __name__ == '__main__':
    unittest.main()