import re

from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.shortcuts import render, redirect, reverse, HttpResponse
from django.views.generic import View
from itsdangerous import SignatureExpired
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from goods.models import GoodsSKU

from celery_tasks.tasks import send_register_active_email
from user.models import User
from django.contrib.auth.hashers import check_password

from utils.mixin import LoginRequiredMixin
from user.models import Address


def register(request):
    if request.method == 'GET':
        """显示注册页面"""
        return render(request, "register.html")
    else:
        """进行注册处理"""
        # 接收数据
        username = request.POST.get('user_name')
        password = request.POST.get('pwd')
        email = request.POST.get('email')
        allow = request.POST.get("allow")
        # 进行数据效验
        if not all([username, password, email]):
            # 数据不完整
            return render(request, 'register.html', {'errmsg': '数据不完整'})

        # 效验邮箱
        if not re.match(r'^[a-z0-9][\w.\-]*@[a-z0-9\-]+(\.[a-z]{2,5}){1,2}$', email):
            return render(request, 'register.html', {'errmsg': '邮箱格式不正确'})

        if allow != 'on':
            return render(request, 'register.html', {'errmsg': '请同意协议'})
        # 效验用户名是否重复
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            user = None

        if user:
            # 用户名已存在
            return render(request, 'register.html', {'errmsg': '用户名已存在'})

        # 进行业务处理：进行哦用户注册
        user = User.objects.create_user(username, email, password)
        user.is_active = 0
        user.save()

        # 返回应答: 跳转到首页
        return redirect(reverse('goods:index'))


class RegisterView(View):
    """注册视图类"""

    def get(self, request):
        """显示注册页面"""
        return render(request, 'register.html')

    def post(self, request):
        # 接收数据
        username = request.POST.get('user_name')
        password = request.POST.get('pwd')
        email = request.POST.get('email')
        allow = request.POST.get("allow")
        # 进行数据效验
        if not all([username, password, email]):
            # 数据不完整
            return render(request, 'register.html', {'errmsg': '数据不完整'})

        # 效验邮箱
        if not re.match(r'^[a-z0-9][\w.\-]*@[a-z0-9\-]+(\.[a-z]{2,5}){1,2}$', email):
            return render(request, 'register.html', {'errmsg': '邮箱格式不正确'})

        if allow != 'on':
            return render(request, 'register.html', {'errmsg': '请同意协议'})
        # 效验用户名是否重复
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            user = None

        if user:
            # 用户名已存在
            return render(request, 'register.html', {'errmsg': '用户名已存在'})

        # 进行业务处理：进行用户注册
        user = User.objects.create_user(username, email, password)
        user.is_active = 0
        user.save()
        # 发送激活邮件， 包含激活连接: http://127.0.0.1:8000/user/active/用户ID
        # 激活连接中需要包含用户的身份信息
        # 加密用户的身份信息，生成激活的token
        serializer = Serializer(settings.SECRET_KEY, 3600)
        info = {"confirm": user.id}
        token = serializer.dumps(info)  # bytes类型
        token = token.decode('utf8')

        # 发邮件
        send_register_active_email.delay(email, username, token)

        # 返回应答: 跳转到首页
        return redirect(reverse('goods:index'))


class ActiveView(View):
    """用户激活"""

    def get(self, request, token):
        """进行用户账号激活"""
        # 进行解密，获取要激活的用户信息
        serializer = Serializer(settings.SECRET_KEY, 3600)
        try:
            info = serializer.loads(token)
            # 获取激活用户的ID
            user_id = info["confirm"]
            # 根据id获取用户信息
            user = User.objects.get(id=user_id)
            user.is_active = 1
            user.save()
            # 跳转到登录页面
            return redirect(reverse('user:login'))
        except SignatureExpired as e:
            # 激活链接已过期
            return HttpResponse("激活链接已过期")


class LoginView(View):
    """登录"""

    def get(self, request):
        """显示登录页面"""
        # 是否记录了用户名
        if 'username' in request.COOKIES:
            username = request.COOKIES.get('username')
            checked = 'checked'
        else:
            username = ''
            checked = ''
        # 使用模板
        return render(request, 'login.html', {'username': username, 'checked': checked})

    def post(self, request):
        """登录效验"""
        # 接收数据
        username = request.POST.get('username')
        password = request.POST.get('pwd')

        # 效验数据
        if not all([username, password]):
            return render(request, 'login.html', {'errmsg': '数据不完整'})

        # 业务处理：登录效验
        # user = authenticate(username=username, password=password)  # 有问题
        user = User.objects.get(username=username)
        pwd = user.password
        # 用户名密码正确
        if check_password(password, pwd):
            if user.is_active:
                # 用户已激活
                # 记录用户的登录状态(将session存在redis中去)
                login(request, user)
                # 跳转到登录后索要跳转到的地址
                # 默认跳转到首页
                next_url = request.GET.get('next', reverse('goods:index'))

                response = redirect(next_url)  # response对象
                # 判断是否需要记录用户名
                remember = request.POST.get('remember')
                if remember == 'on':
                    # 记住用户名
                    response.set_cookie('username', username, max_age=7 * 24 * 3600)
                else:
                    response.delete_cookie('username')
                # 跳转到首页
                return response

            else:
                # 用户未激活
                return render(request, 'login.html', {'errmsg': '账号未激活'})
        else:
            # 用户名或者密码错误
            return render(request, 'login.html', {'errmsg': '用户名或者密码错误'})


# /user/logout
class LogoutView(View):
    """退出登录"""

    def get(self, request):
        """退出登录"""
        # 清除用户的session信息
        logout(request)

        # 跳转到首页
        return redirect(reverse('goods:index'))


# /user
class UserInfoView(LoginRequiredMixin, View):
    """用户中心-信息页"""

    def get(self, request):
        """显示"""
        # 如果用户未登录 --> AnonymousUser类的一个实例
        # 如果用户登录--> User类的一个实例
        # 除了你给模板文件传递的模板变量之外， django框架会把request.user也传递给模板文件
        # 通过request.user.is_authenticated()判断有没有登录
        # 获取用户的个人信息
        user = request.user
        address = Address.objects.get_default_address(user)
        # 获取用户的历史浏览记录
        # from redis import StrictRedis
        # str = StrictRedis(host='192.168.0.113', port='6379', db=9)
        from django_redis import get_redis_connection
        con = get_redis_connection('history')
        history_key = 'history_%d' % user.id
        # 获取用户最新浏览的5个商品id
        sku_ids = con.lrange(history_key, 0, 4)  # [2 ,3, 1]
        # 从数据库中查询用户浏览的具体商品信息
        goods_li = []
        for id in sku_ids:
            goods = GoodsSKU.objects.get(id=id)
            goods_li.append(goods)
        # 组织上下文
        context = {'page': 'user',
                   'address': address,
                   'goods_li': goods_li}

        return render(request, 'user_center_info.html', context)


# /user/order
class UserOrderView(LoginRequiredMixin, View):
    """用户中心-订单页"""

    def get(self, request):
        """显示"""
        # 获取用户的订单信息

        return render(request, 'user_center_order.html', {'page': 'order'})


# user/address
class AddressView(LoginRequiredMixin, View):
    """用户中心-地址页"""

    def get(self, request):
        """显示"""
        # 获取用户的默认收货地址
        user = request.user
        # try:
        #     address = Address.objects.get(user=user, is_default=True)
        # except Address.DoesNotExist:
        #     # 不存在收货地址
        #     address = None
        address = Address.objects.get_default_address(user)

        return render(request, 'user_center_site.html', {'page': 'address', 'address': address})

    def post(self, request):
        """地址的添加"""

        # 接收数据
        receiver = request.POST.get('receiver')
        addr = request.POST.get('addr')
        zip_code = request.POST.get('zip_code')
        phone = request.POST.get('phone')

        # 效验数据
        if not all([receiver, addr, phone, ]):
            return render(request, 'user_center_site.html', {'errmsg': "数据不完整"})
        # 效验手机号
        if not re.match(r'^1[3|4|5|7|8][0-9]{9}$', phone):
            return render(request, 'user_center_site.html', {'errmsg': '手机格式不正确'})

        # 业务处理：地址添加
        # 如果用户已存在默认地址，添加的地址不作为默认收货地址， 否则作为默认收货地址
        # 获取登录用户对应的用户对象
        user = request.user
        # try:
        #     address = Address.objects.get(user=user, is_default=True)
        # except Address.DoesNotExist:
        #     # 不存在收货地址
        #     address = None
        address = Address.objects.get_default_address(user)
        if address:
            is_default = False
        else:
            is_default = True

        # 添加地址
        Address.objects.create(user=user,
                               receiver=receiver,
                               addr=addr,
                               zip_code=zip_code,
                               phone=phone,
                               is_default=is_default)
        # 返回应答, 刷新地址页面
        return redirect(reverse('user:address'))  # get请求方式
