from django.core.files.storage import Storage
from fdfs_client.client import Fdfs_client


class FDFSStorage(Storage):
    """fast dfs 文件存储类"""

    def _open(self, name, mode='rb'):
        '''打开文件时使用'''
        pass

    def _save(self, name, content):
        '''保存文件时使用'''
        # name：你选择上传文件的名字
        # content: 包含你上传文件内容的File对象
        # 创建一个Fdfs_client对象
        client = Fdfs_client('./utils/fdfs/client.conf')

        # 上传文件到fast dfs系统中
        res = client.upload_appender_by_buffer(content.read())
        # {
        #     'Group name': group_name,
        #     'Remote file_id': remote_file_id,
        #     'Status': 'Upload successed.',
        #     'Local file name': '',
        #     'Uploaded size': upload_size,
        #     'Storage IP': storage_ip
        # } if success else None
        if res.get('Status') != 'Upload successed.':
            # 上传失败
            raise Exception('上传文件到fast dfs失败')
        # 获取返回的文件ID
        file_name = res.get('Remote file_id')
        return file_name

    def exists(self, name):
        # 如果提供的名称在文件系统中存在，则返回True
        return False
