from django.urls import re_path
from user.views import RegisterView, ActiveView, LoginView

urlpatterns = [
    # path('register', views.register, name='register'),  # 注册
    re_path('^register$', RegisterView.as_view(), name='register'),  # 注册
    re_path('^active/(?P<token>.*)$', ActiveView.as_view(), name='active'),  # 激活
    re_path('^login$', LoginView.as_view(), name='login'),  # 登录
]
