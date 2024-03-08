
from django.contrib import admin
from django.urls import path, include
from . import views
from .consumers import PacketConsumer,AnomalyPredictionConsumer,SecurityPredictionConsumer

urlpatterns = [
    path('',views.home, name='home'),
    path('signup',views.signup,name='signup'),
    path('signin',views.signin,name='signin'),
    path('signout',views.signout,name='signout'),
    path('sniff', views.sniff_packets, name='sniff_packets'),
    path("predictions", views.predictions, name="predictions"),
    path("trial", views.trial, name="trial"),
    path('admin-panel',views.admin_panel, name="admin_panel"),
    path('approve-user/<int:user_id>/', views.approve_user, name='approve_user'),
]


from django.urls import re_path
from .consumers import PacketConsumer

websocket_urlpatterns = [
    re_path(r'ws/packet/$', PacketConsumer.as_asgi()),
    re_path(r'ws/anomalyprediction/$', AnomalyPredictionConsumer.as_asgi()),
    re_path(r'ws/securityprediction/$', SecurityPredictionConsumer.as_asgi()),
]