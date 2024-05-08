
from django.contrib import admin
from django.urls import path, include
from . import views
from .consumers import PacketConsumer,AnomalyPredictionConsumer,SecurityPredictionConsumer, DashBoardConsumer

urlpatterns = [
    path('',views.landingpage, name='home'),
    path('signup',views.signup,name='signup'),
    path('signin',views.signin,name='signin'),
    path('signout',views.signout,name='signout'),
    path('sniff', views.sniff_packets, name='sniff_packets'),
    path("predictions", views.predictions, name="predictions"),
    path("trial", views.trial, name="trial"),
    path('admin-panel',views.admin_panel, name='admin_panel'),
    path('approve-user/<int:user_id>/', views.approve_user, name='approve_user'),
    path('alerts',views.alerts, name="alerts"),
    path('dashboard',views.dashboard, name="dashboard"),
    path('anomalyreports',views.anomalyreports, name="anomalyreports"),
    path('securityreports',views.securityreports, name="securityreports"),
    path('change_password', views.change_password, name='change_password'),

    # path('get_last_12_entries/', views.get_last_12_entries, name='get_last_12_entries'),
]


from django.urls import re_path
from .consumers import PacketConsumer

websocket_urlpatterns = [
    re_path(r'ws/packet/$', PacketConsumer.as_asgi()),
    re_path(r'ws/allpackets/$', DashBoardConsumer.as_asgi()),
    re_path(r'ws/anomalyprediction/$', AnomalyPredictionConsumer.as_asgi()),
    re_path(r'ws/securityprediction/$', SecurityPredictionConsumer.as_asgi()),
]