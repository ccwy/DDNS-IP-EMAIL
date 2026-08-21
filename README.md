# DDNS-IP-EMAIL

适用于群晖DDNS IP变动通过SMTP邮件提醒，家庭宽带动态公网IPV4每隔段时间就会自动更新，更新了自己也不知道，就使用GO语言写个轻量docker用于通知用户IP变动

使用很简单，配置SMTP发件服务，填入收件邮箱，保存即可。后台会自动检测并发送邮件通知你。

使用方法：

1，下载打包好的镜像，下载地址：https://github.com/ccwy/DDNS-IP-EMAIL/releases

2，在群晖Container Manager里面，点击映像-操作-导入-从文件添加-从本地设备，选择你下载的镜像。

3，点击上传的镜像，点击运行-按图填写-下一步

<img width="747" height="584" alt="image" src="https://github.com/user-attachments/assets/a0e3461a-81b7-442d-ad04-d976c9a5caf4" />

4，存储空间，点击添加文件夹，选择你本地文件夹，输入框输入/data ，权限选择读写。这里是数据存储位置。

<img width="740" height="578" alt="image" src="https://github.com/user-attachments/assets/94845d97-8d72-4ae9-8092-6f8528b1f89c" />

5，点击下一步，点击完成，点击进入web station,，配置外部访问端口，门户类型选择基于端口，你可以自己选择http或者https，然后点击新增。

<img width="1920" height="919" alt="image" src="https://github.com/user-attachments/assets/4208fdeb-cfc8-4c26-ad6e-638e71a37a76" />

6，访问你的端口，默认端口是49809，但你需要根据你在web station实际选择的端口来访问。

<img width="1920" height="919" alt="image" src="https://github.com/user-attachments/assets/2a0f397b-e723-4252-9eda-85d200bf9c3c" />

7，配置你自己的SMTP信息，这里使用的标准SMTP，支持SSL。

8，点击保存并测试，就可以收到测试邮件了。
