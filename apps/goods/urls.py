from django.urls import re_path
from goods import views

urlpatterns = [
    re_path('^$', views.index, name= "index"),
]
