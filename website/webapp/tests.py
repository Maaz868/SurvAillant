from django.test import TestCase
from django.urls import reverse
from django.contrib.auth.models import User
from .models import CustomUser, NetworkTraffic, ProtocolCount, SecurityTraffic, AnomalyPackets, SecurityPackets


class DjangoViewsTestCase(TestCase):
    def setUp(self):
        self.user_data = {
            'username': 'maaz',
            'email': 'maaz@example.com',
            'password': 'maaz',
            # 'confirm_password': 'maaz',
        }
        self.user = CustomUser.objects.create_user(**self.user_data)


    def test_signup_mismatched_passwords(self):
        self.user_data['confirm_password'] = 'mismatchedpassword'
        response = self.client.post(reverse('signup'), data=self.user_data)
        self.assertEqual(response.status_code, 200)  # Form submission failed, stays on the same page

    def test_signup_existing_username(self):
        existing_user_data = {
            'username': 'maaz',
            'email': 'newuser@example.com',
            'password': 'newpassword',
            'confirm_password': 'newpassword',
        }
        response = self.client.post(reverse('signup'), data=existing_user_data)
        self.assertEqual(response.status_code, 200)  # Form submission failed, stays on the same page

    def test_signin_correct_credentials(self):
        response = self.client.post(reverse('signin'), data={'username': 'maaz', 'password': 'maaz'})
        self.assertEqual(response.status_code, 302)  # Redirect status code

    def test_signin_incorrect_credentials(self):
        response = self.client.post(reverse('signin'), data={'username': 'maaz', 'password': 'wrongpassword'})
        self.assertEqual(response.status_code, 302)  
        
    def test_dashboard_view_authenticated(self):
        self.client.login(username='maaz', password='maaz')
        response = self.client.get(reverse('dashboard'))
        self.assertEqual(response.status_code, 200)

    def test_signout_view(self):
        self.client.login(username='maaz', password='maaz')
        response = self.client.get(reverse('signout'))
        self.assertEqual(response.status_code, 200)

    def test_sniff_packets_view_authenticated(self):
        self.client.login(username='maaz', password='maaz')
        response = self.client.get(reverse('sniff_packets'))
        self.assertEqual(response.status_code, 200)

    def test_sniff_packets_view_unauthenticated(self):
        response = self.client.get(reverse('sniff_packets'))
        self.assertEqual(response.status_code, 302)  

    def test_anomaly_reports_view_authenticated(self):
        self.client.login(username='maaz', password='maaz')
        response = self.client.get(reverse('anomaly_reports'))
        self.assertEqual(response.status_code, 200)

    def test_anomaly_reports_view_unauthenticated(self):
        response = self.client.get(reverse('anomaly_reports'))
        self.assertEqual(response.status_code, 302)  

    def test_security_reports_view_authenticated(self):
        self.client.login(username='maaz', password='maaz')
        response = self.client.get(reverse('security_reports'))
        self.assertEqual(response.status_code, 200)

    def test_security_reports_view_unauthenticated(self):
        response = self.client.get(reverse('security_reports'))
        self.assertEqual(response.status_code, 302)
        
    def test_sniff_packets_view_authenticated(self):
        self.client.login(username='maaz', password='maaz')
        response = self.client.get(reverse('sniff_packets'))
        self.assertEqual(response.status_code, 200)

    def test_sniff_packets_view_unauthenticated(self):
        response = self.client.get(reverse('sniff_packets'))
        self.assertEqual(response.status_code, 302) 

    def test_anomaly_reports_view_authenticated(self):
        self.client.login(username='maaz', password='maaz')
        response = self.client.get(reverse('anomalyreports'))
        self.assertEqual(response.status_code, 200)

    def test_anomaly_reports_view_unauthenticated(self):
        response = self.client.get(reverse('anomalyreports'))
        self.assertEqual(response.status_code, 302) 

    def test_security_reports_view_authenticated(self):
        self.client.login(username='maaz', password='maaz')
        response = self.client.get(reverse('securityreports'))
        self.assertEqual(response.status_code, 200)

    def test_security_reports_view_unauthenticated(self):
        response = self.client.get(reverse('securityreports'))
        self.assertEqual(response.status_code, 302)
