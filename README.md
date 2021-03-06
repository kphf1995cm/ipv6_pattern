## 简介
基于IPv6地址训练集自动发现一些最符合这些IPv6地址的模式，并利用这些模式按照升序地方式自动产生IPv6地址扫描列表
## 环境
*windows*+*pycharm*
## 算法
基于IPv6地址训练集自动发现IPv6地址模式的算法是递归的，并且会在每次递归过程中确定一个额外位的取值以此改进给定模式。这个额外位的选择是所有候选模式中覆盖最大数量IPv6地址中的那一个。在每次遍历过程中，确定位数量会增加1，当确定位数量增加到一个阈值时，模式生成结束，IPv6地址扫描列表生成开始，所有符合当前模式的地址会以升序地方式逐渐产生。算法具体流程如下：
1. 确定一个初始模式。初始模式中至少包含一个确定位，由于IPv6地址由128位二进制数字，所以总共有2^128=256种初始模式。
2. 在当前模式的基础上，确定一个额外位取值。对于每一个额外位，计算在其取值为0或1的情况下符合当前模式及该额外位取值的IPv6地址数，比较各个额外位取值所对应的IPv6地址数，挑选出IPv6地址数最大的那一个额外位取值。假设当前模式为01xx，比较发现符合010x数量为1，符合011x数量为3，符合01x0数量为4，符合01x1数量为2，则下一个模式为01x0。kp
3. 重复第二步过程，直到当前模式种确定位数量大于临界阈值，该当前模式即为所生成的IPv6模式。
4. 基于生成的IPv6模式，遍历未确定位所有取值的可能，生成IPv6地址扫描列表。
## 参考文献
Ullrich J, Kieseberg P, Krombholz K, et al. On reconnaissance with IPv6: a pattern-based scanning approach[C]//Availability, Reliability and Security (ARES), 2015 10th International Conference on. IEEE, 2015: 186-192.
