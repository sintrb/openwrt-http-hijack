openwrt-http-hijack
===================

Python实现的OpenWRT的HTTP截获工具

# 安装
* 安装Python
<pre><code>opkg update
opkg install python
</code></pre>
* 安装python-pcap
<pre><code>opkg install python-pcap</code></pre>

* 安装python-dpkg
到dpkg项目官网[https://code.google.com/p/dpkt/](https://code.google.com/p/dpkt/)下载源代码，纯Python的，解压之后进入项目文件夹使用setup安装。
<pre><code>python setup.py install</code></pre>


# 使用
<pre><code>python hijack.py</code></pre>
