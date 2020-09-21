from django.urls import re_path
from user.views import RegisterView

urlpatterns = [
    # path('register', views.register, name='register'),  # 注册
    re_path('register', RegisterView.as_view(), name='register'),  # 注册
]
