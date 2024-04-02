# logonpasswords

在某次测试360时，发现使用powershell添加用户在是否有网络的情况下拦截的情况略有不同，于是有了这个项目。

（一）有网络时的拦截：

![enable_network](https://github.com/BambiZombie/logonpasswords/assets/84751437/1719c2b6-6556-4db3-a0b7-612bad32f39e)

（二）无网络时的拦截：

![disable_network](https://github.com/BambiZombie/logonpasswords/assets/84751437/4456153e-61a1-4161-a2cf-b98e82f2b99d)

应该很容易发现两者之间的差别，虽然不清楚具体的细节，但通过对比我们知道360在有网络时一定进行了某种更深层次的检测。那么既然360在有无网络的情况下的检测能力不同，我们是不是可以利用这一点来致盲360呢。在ChangeNetStateC.h里我通过COM的方式遍历网卡并禁用网卡1秒，从而实现了在360核晶环境下的logonpasswords。

![logonpasswords](https://github.com/BambiZombie/logonpasswords/assets/84751437/154c6449-ff37-4146-9b8c-c50c23062c55)


## 免责声明

该工具仅用于网络安全学习

由于传播、利用此工具所提供的信息而造成的后果失，均由使用者负责，作者不为此承担任何责任。

未经网络安全部门及相关部门允许，不得善自使用本工具进行任何攻击活动。

该工具只用于个人学习，请勿用于非法用途，请遵守网络安全法，否则后果作者概不负责。
