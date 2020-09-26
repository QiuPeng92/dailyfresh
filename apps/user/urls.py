from django.urls import re_path
from user.views import RegisterView, ActiveView, LoginView, UserInfoView, UserOrderView, AddressView
from django.contrib.auth.decorators import login_required

urlpatterns = [
    # path('register', views.register, name='register'),  # 注册
    re_path('^register$', RegisterView.as_view(), name='register'),  # 注册
    re_path('^active/(?P<token>.*)$', ActiveView.as_view(), name='active'),  # 激活
    re_path('^login$', LoginView.as_view(), name='login'),  # 登录
    # re_path('^$', login_required(UserInfoView.as_view()), name='user'),  # 用户中心-信息页
    # re_path('^order$', login_required(UserOrderView.as_view()), name='order'),  # 用户中心-订单页
    # re_path('^address$', login_required(AddressView.as_view()), name='address'),  # 用户中心-地址页
    re_path('^$', UserInfoView.as_view(), name='user'),  # 用户中心-信息页
    re_path('^order$', UserOrderView.as_view(), name='order'),  # 用户中心-订单页
    re_path('^address$', AddressView.as_view(), name='address'),  # 用户中心-地址页

]
