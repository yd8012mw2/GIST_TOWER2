from django.urls import path

from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('getStatus', views.getStatus, name='getStatus'),
    path('getUpdate', views.getUpdate, name='getUpdate')
]

