#!/usr/bin/python
# -*- coding: utf-8 -*-

# function@generate ipv6 patterns
# time@2018-12-4
# author@kuangp  

# ipv6 standard format:0x1111222233334444555566667777ffff

import xlrd
import csv
import heapq

train_ipv6_list=[] #  ipv6地址的16进制表示,整数型，训练集
test_ipv6_list=[] # 测试集
threshold=120 # minimal determined bit num,global variable
pattern_det_bit_set={} # pattern:det_bit_set  
ipv6_width=128
ipv6_scanning_list_dict=[] # 模式:扫描列表 

char_set={'0':0,'1':1,'2':2,'3':3,'4':4,'5':5,'6':6,'7':7,'8':8,'9':9
,'a':10,'b':11,'c':12,'d':13,'e':14,'f':15}

class PriorityQueue:
    def __init__(self):
        self._queue = []
        self._index = 0
    def push(self, item):
        heapq.heappush(self._queue, (-item, self._index, item))
        self._index += 1
    def pop(self):
        return heapq.heappop(self._queue)[-1]
    def is_empty(self):
    	if len(self._queue)==0:
    		return True 
    	else:
    		return False

# file ipv6 format:20011218100002300000000000000252
def read_ipv6_from_32_16_txt(ipv6_list,path):
	f=open(path,'r')
	line=f.readline()
	line=line[:-1]

	while line:
		int_ipv6=0
		for x in line:
			int_ipv6=int_ipv6*16+char_set[x]
		ipv6_list.append(int_ipv6)
		line=f.readline()
		line=line[:-1] 

	f.close()

# 先确定下全为相同值（或者熵值相差悬殊）的某些位取值，进行优化
def determine_same_bit():
	pass

# ipv6地址位bit：0123...127
# 想要求取某位的取值 ipv6>>(128-1-bit)
# spe_bit_set
def compare_specfic_bit(pattern_int,ipv6_int,spe_bit_set):
	for bit in spe_bit_set:
		#print(bit,end=' ')
		if (pattern_int>>(ipv6_width-1-bit))&1!=(ipv6_int>>(ipv6_width-1-bit))&1:
			return False
	return True
# 因为pattern最初时为全0，所以bit_value为1时，才需要做这步
def spe_pattern_in_bit(pattern,bit_index,bit_value):
	pri_pattern=pattern
	pattern=pattern>>(ipv6_width-1-bit_index)
	pattern=pattern | bit_value
	pattern=pattern<<(ipv6_width-1-bit_index)
	return pattern | pri_pattern

# 参数： 当前模式 确定位数量 确定位所在的位置（从大到小排列，优先级队列实现） 确定位所在的位置（set 集合实现）
# 参数传递过程会爆内存
def iterate_pattern(pattern,determined_num,det_bit_set):
	if determined_num>=threshold:
		pattern_det_bit_set[pattern]=det_bit_set
	else:
		max_match_num=0 #最大匹配数 
		max_bit_index=-1 #最大匹配数对应的位
		# 从后往前遍历
		bit_index=ipv6_width-1
		while bit_index>=0:
			if bit_index not in det_bit_set:
				condidate_pattern_1=spe_pattern_in_bit(pattern,bit_index,1)
				#print("condidate_pattern_1",'%#x'%condidate_pattern_1)
				condidate_pattern_0=pattern
				det_bit_set.add(bit_index)
				cur_match_num_1=0
				cur_match_num_0=0
				for ipv6 in train_ipv6_list:
					if compare_specfic_bit(condidate_pattern_1,ipv6,det_bit_set)==True:
						cur_match_num_1=cur_match_num_1+1
					else:
						if compare_specfic_bit(condidate_pattern_0,ipv6,det_bit_set)==True:
							cur_match_num_0=cur_match_num_0+1
				det_bit_set.remove(bit_index)
				if cur_match_num_1>max_match_num:
					max_match_num=cur_match_num_1
					max_bit_index=bit_index
					pattern=condidate_pattern_1

				if cur_match_num_0>max_match_num:
					max_match_num=cur_match_num_0
					max_bit_index=bit_index
					pattern=condidate_pattern_0
			bit_index=bit_index-1
		if max_match_num>0:	# 限定至少存在一种匹配方式，防止生成无效模式
			det_bit_set.add(max_bit_index)
			#print('best_pattern','%#x'%pattern)
			#print('determined bit:',end=' ')
			#for x in det_bit_set:
			#	print(x,end=' ')
			#Sprint(' ')
			iterate_pattern(pattern,determined_num+1,det_bit_set)

# 从后往前遍历
def iterate_gen_ipv6_scanning_list(pattern,det_bit_set,det_bit_num,bit_index,ipv6_scanning_list):
	if det_bit_num>=ipv6_width:
		ipv6_scanning_list.append(pattern)
	else:
		while bit_index>=0:
			if bit_index not in det_bit_set:
				pattern_1=spe_pattern_in_bit(pattern,bit_index,1) #设置为1
				iterate_gen_ipv6_scanning_list(pattern_1,det_bit_set,det_bit_num+1,bit_index-1,ipv6_scanning_list)
				iterate_gen_ipv6_scanning_list(pattern,det_bit_set,det_bit_num+1,bit_index-1,ipv6_scanning_list)
				break
			else:
				bit_index=bit_index-1

# 遍历前prefix_len位
def gen_ipv6_all_pattern(prefix_len):
	pattern=0x00000000000000000000000000000000
	for index in range(prefix_len):
		s_pattern=(spe_pattern_in_bit(pattern,index,1)) #将特定位设置为1
		det_bit_set_1=set()
		det_bit_set_1.add(index)
		det_bit_set_0=set()
		det_bit_set_0.add(index)
		iterate_pattern(s_pattern,1,det_bit_set_1)
		iterate_pattern(pattern,1,det_bit_set_0) #将特定位设置为0

# 参数：Ipv6模式 确定位集合
def gen_ipv6_scanning_list(pattern,det_bit_set):
	ipv6_scanning_list=[]
	iterate_gen_ipv6_scanning_list(pattern,det_bit_set,len(det_bit_set),ipv6_width-1,ipv6_scanning_list)
	return ipv6_scanning_list

def gen_ipv6_all_scanning_list():
	for pattern in pattern_det_bit_set.keys():
		ipv6_scanning_list_dict[pattern]=gen_ipv6_scanning_list(pattern,pattern_det_bit_set[pattern])



def print_16_list(value_list):
	for x in value_list:
		print('%#x'%x)

def print_pattern_det_bit_set():
	for x in pattern_det_bit_set.keys():
		print('%#x'%x)
		det_bit_set=pattern_det_bit_set[x]
		for y in det_bit_set:
			print(y,end=' ')
		print(' ')

def print_16(x):
	print('%#x'%x)

def test_compare_specfic_bit():
	x1=0xffff0000000000000000000000000000 
	x2=0xfffe0000000000000000000000000000 
	spe_bit_set=set()
	spe_bit_set.add(0)
	spe_bit_set.add(1)
	spe_bit_set.add(15)
	if compare_specfic_bit(x1,x2,spe_bit_set)==True:
		print("right")
	else:
		print("false")

def ipv6_scan_gen_test():
	pattern=0xffff0000000000000000000000000000
	det_bit_set=set()
	for i in range(120):
		det_bit_set.add(i)
	ipv6s=gen_ipv6_scanning_list(pattern,det_bit_set)
	for x in ipv6s:
		print_16(x)
	print(len(ipv6s))

def test_iterate_pattern():
	s=set()
	s.add(0)
	s.add(1)
	s.add(2)
	s.add(3)
	iterate_pattern(0x20000000000000000000000000000000,4,s)

def print_ipv6_scanning_list_dict():
	for pattern in ipv6_scanning_list_dict.keys():
		print_16(pattern)
		print_16_list(ipv6_scanning_list_dict[pattern])
		print(len(ipv6_scanning_list_dict[pattern]))

if __name__=='__main__':
	
	read_ipv6_from_32_16_txt(train_ipv6_list,'D:/DataSet/responsive-addresses/sample.txt')
	gen_ipv6_all_pattern(4)
	print_pattern_det_bit_set()
	gen_ipv6_all_scanning_list()
	print(len(ipv6_scanning_list_list))
	print_ipv6_scanning_list_dict()

	#ipv6_scan_gen_test()

