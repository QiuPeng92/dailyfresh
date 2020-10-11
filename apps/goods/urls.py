from django.urls import re_path
from goods.views import IndexView, DetailView, ListView

urlpatterns = [
    re_path('^index$', IndexView.as_view(), name="index"),  # 首页
    re_path('^goods/(?P<goods_id>\d+)$', DetailView.as_view(), name="detail"),  # 详情页
]
