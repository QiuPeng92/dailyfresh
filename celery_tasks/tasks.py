# 使用celery
from celery import Celery
from django.conf import settings
from django.core.mail import send_mail

# django环境的初始化
# import os
# import django
# os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'dailyfresh.settings')
# django.setup()


# 创建一个Celery类的实例对象
app = Celery('celery_tasks.tasks', broker='redis://192.168.0.111:6379/8')


# 定义任务函数
@app.task
def send_register_active_email(to_email, username, token):
    """发送激活邮件"""
    # 组织邮件信息
    subject = "天天生鲜欢迎信息"
    message = ''
    html_message = '<h1>%s ,欢迎您成为天天生鲜注册会员，请点击以下链接激活您的账号</h1><br/><a href="http://127.0.0.1:8000/user/active/%s">http://127.0.0.1:8000/user/active/%s</a>' % (
        username, token, token)
    sender = settings.EMAIL_FROM
    receiver = [to_email]
    send_mail(subject, message, sender, receiver, html_message=html_message)
