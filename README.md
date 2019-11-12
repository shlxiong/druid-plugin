# druid-plugin
DruidDataSource安全插件以及调用链的过滤器

# 问题起源
    熟悉Druid的开发者，可以通过ApplicationContext拿到DruidDataSource对象，进而通过getPassword()取得数据库的密码；
    再次一点，还可以ConfigTools解出配置文件中加密密码，因为大部分公司都是简单地使用ConfigTools.decrypt()做一下加密就保存起来。
    
# 解决办法
    1、DruidDataSource的变量不可保存密码明文，而是在连接数据库的时候实时的做解密；
    2、通过非对称证书去加/解密，而不是使用默认的ConfigTools；
    3、有条件的，可以通过一个分布式文件系统（比如CEPH）来存储证书，然后通过HTTP来请求获取证书。
