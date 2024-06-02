# logonpasswords

去除了mimikatz中除logonpasswords功能外的代码，增加ChangeNetStateC.h绕过某杀软。

## 说明

某杀软在有互联网情况下对Powershell添加用户的拦截情况：

![enable_network](https://github.com/BambiZombie/logonpasswords/assets/84751437/c76d7995-38a8-4a6b-9cb4-c7e714081a85)

断网情况下的拦截情况：

![disable_network](https://github.com/BambiZombie/logonpasswords/assets/84751437/86c9f98a-207c-4160-8d26-b659c94940d5)

可以非常清楚的看到两者之间的区别，说明某杀软在联网状态下进行了更深层次的检测，利用该特点DumpLsass，效果如下：

![logonpasswords](https://github.com/BambiZombie/logonpasswords/assets/84751437/0c017e25-3f94-4c99-9d68-954f5150fc9d)



## 免责声明

该工具仅用于网络安全学习

由于传播、利用此工具所提供的信息而造成的后果失，均由使用者负责，作者不为此承担任何责任。

未经网络安全部门及相关部门允许，不得善自使用本工具进行任何攻击活动。

该工具只用于个人学习，请勿用于非法用途，请遵守网络安全法，否则后果作者概不负责。
