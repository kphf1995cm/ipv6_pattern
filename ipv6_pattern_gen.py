#!/usr/bin/python
# -*- coding: utf-8 -*-

# function@generate ipv6 patterns
# time@2018-12-4
# author@kuangp  

# ipv6 standard format:0x1111222233334444555566667777ffff

import xlrd
import csv
import heapq
import datetime
import time

train_ipv6_list=[] #  ipv6地址的16进制表示,整数型，训练集
test_ipv6_list=set() # 测试集
threshold=108 # minimal determined bit num,global variable
pattern_det_bit_set={} # pattern:det_bit_set  
ipv6_width=128
start_prefix_len=16
ipv6_scanning_list_dict={} # 模式:扫描列表 

char_set={'0':0,'1':1,'2':2,'3':3,'4':4,'5':5,'6':6,'7':7,'8':8,'9':9
,'a':10,'b':11,'c':12,'d':13,'e':14,'f':15}

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

# file ipv6 format:20011218100002300000000000000252
def read_ipv6_from_32_16_txt_gen_set(ipv6_list,path):
	f=open(path,'r')
	line=f.readline()
	line=line[:-1]

	while line:
		int_ipv6=0
		for x in line:
			int_ipv6=int_ipv6*16+char_set[x]
		ipv6_list.add(int_ipv6)
		line=f.readline()
		line=line[:-1] 
	f.close()

# func: ipv6 address formulate, remove duplicate ipv6 address
# input: ipv6 address txt file path
# output: generate a formatting ipv6 address file
# test_sum/train_sum=ratio ratio>1
def read_write_data_fromin_txt(path,train_sum,ratio):

	f=open(path,'r')
	path_seg=path.split('.')
	testpath=path_seg[0]+'-test0'+'.txt'
	trainpath=path_seg[0]+'-train0'+'.txt'
	test=open(testpath,'w')
	train=open(trainpath,'w')

	line=f.readline()
	line=line[:-1]

	ipv6_dict={}

	# ignore first line
	while line:
		line=f.readline()
		line=line[:-1]
		#print(line)
		gen_line=ipv6_formate(line)
		#print('%#x'%gen_line)
		dst_line=str(hex(gen_line))
		ipv6_dict[dst_line[2:]]=1

	train_num=0
	ipv6_dict_keys=ipv6_dict.keys()
	index=0
	for x in ipv6_dict_keys:
		if index<ratio:
			test.writelines(x+'\n')
		else:
			train_num=train_num+1
			train.writelines(x+'\n')
			if train_num>train_sum:
				break
		index=(index+1)%(ratio+1)
	print(train_num,ratio)
	f.close()
	test.close()
	train.close()

def gen_train_data_txt(path,start_point,train_num):

	f=open(path,'r')
	path_seg=path.split('.')
	trainpath=path_seg[0]+'-trainnum'+'.txt'
	train=open(trainpath,'w')

	line=f.readline()
	line=line[:-1]

	ipv6_dict={}

	# ignore first line
	while line:
		line=f.readline()
		line=line[:-1]
		#print(line)
		gen_line=ipv6_formate(line)
		#print('%#x'%gen_line)
		dst_line=str(hex(gen_line))
		ipv6_dict[dst_line[2:]]=1

	num=0
	s=0
	ipv6_dict_keys=ipv6_dict.keys()
	for x in ipv6_dict_keys:
		if s<start_point:
			s=s+1
			continue
		train.writelines(x+'\n')
		num=num+1
		if num>=train_num:
			break
	f.close()
	train.close()

def gen_all_testdata_txt(path):

	f=open(path,'r')
	path_seg=path.split('.')
	testpath=path_seg[0]+'-testall'+'.txt'
	test=open(testpath,'w')

	line=f.readline()
	line=line[:-1]

	ipv6_dict={}

	# ignore first line
	while line:
		line=f.readline()
		line=line[:-1]
		#print(line)
		gen_line=ipv6_formate(line)
		#print('%#x'%gen_line)
		dst_line=str(hex(gen_line))
		ipv6_dict[dst_line[2:]]=1

	ipv6_dict_keys=ipv6_dict.keys()
	for x in ipv6_dict_keys:
		test.writelines(x+'\n')
	f.close()
	test.close()

# ipv6 format standrize
# input: 2001:1210:100:1::17
# return:       
def ipv6_formate(raw_ipv6):
	#print(raw_ipv6,'%%',end=' ')
	raw_ipv6=raw_ipv6.lower()
	ipv6=[]
	width=8
	for x in range(width):
		ipv6.append("0000")
	if raw_ipv6.find('.')!=-1: # exist ipv4 style, need leave 2 segments
		width=7
	start=raw_ipv6.find("::")
	if start!=-1: # exist ipv6 address compression ::
		if start==0: # :: is on the start position
			raw_ipv6=raw_ipv6[2:]
			ipv6_seg=raw_ipv6.split(":")
			seg_len=len(ipv6_seg)
			pos=0
			for x in ipv6_seg:
				ipv6[width-seg_len+pos]=x
				pos=pos+1
		else: # :: is on the middle or end position                                                                                                                                                
			ipv6_fragment=raw_ipv6.split("::")
			# front segment
			ipv6_fseg=ipv6_fragment[0].split(":")
			posf=0
			for x in ipv6_fseg:
				ipv6[posf]=x
				posf=posf+1
			# tail segment
			if len(ipv6_fragment)>1:
				ipv6_tseg=ipv6_fragment[1].split(":")
				tseg_len=len(ipv6_tseg)
				post=0
				for x in ipv6_tseg:
					ipv6[width-tseg_len+post]=x
					post=post+1
	else:
		ipv6_seg=raw_ipv6.split(":")
		pos=0
		for x in ipv6_seg:
			ipv6[pos]=x
			pos=pos+1                                                      
	# judge tail ipv6 segment is ipv4 style
	ipv4_seg=ipv6[6].split(".") 
	if len(ipv4_seg)!=1:
		ipv4=""
		for x in ipv4_seg:
			x_len=len(x)
			digit=0
			for i in range(x_len):
				digit=digit*10+char_set[x[i]]
			ipv4=ipv4+num_set[int(digit/16)]+num_set[digit%16]
		ipv6[6]=ipv4[0:4]
		ipv6[7]=ipv4[4:]

	# fill 0 in ipv6
	for j in range(8):
		if len(ipv6[j])<4:
			fill_num=4-len(ipv6[j])
			for i in range(fill_num):
				ipv6[j]='0'+ipv6[j]
	res=0
	for x in ipv6:
		#print(x,end=' ')
		for y in x:
			res=res*16+char_set[y]
	#print('res:','%#x'%res,' ')
	return res

def extract_ipv6_per_bit_value(ipv6,per_bit_1_num,per_bit_0_num):
	index=ipv6_width-1
	while index>=0:
		if (ipv6>>ipv6_width-1-index)&1==1:
			per_bit_1_num[index]=per_bit_1_num[index]+1
		else:
			per_bit_0_num[index]=per_bit_0_num[index]+1
		index=index-1

# 先确定下全为相同值（或者熵值相差悬殊）的某些位取值，进行优化
# 返回提取出的模式，以及相应的确定位
def get_determine_bit():
	det_bit_pos_set=set()
	det_bit_value_list=[]
	probability_multiply_threshold=0.09
	train_ipv6_list_len=len(train_ipv6_list)
	per_bit_1_num=[]
	per_bit_0_num=[]
	for i in range(ipv6_width):
		per_bit_0_num.append(0)
		per_bit_1_num.append(0) 
	for ipv6 in train_ipv6_list:
		extract_ipv6_per_bit_value(ipv6,per_bit_1_num,per_bit_0_num)
	for i in range(ipv6_width):
		probability_multiply=(per_bit_1_num[i]/train_ipv6_list_len)*(per_bit_0_num[i]/train_ipv6_list_len)
		if probability_multiply<probability_multiply_threshold:
			det_bit_pos_set.add(i)
			if per_bit_1_num[i]>per_bit_0_num[i]:
				det_bit_value_list.append(1)
			else:
				det_bit_value_list.append(0)

	# build pattern
	pattern=0x00000000000000000000000000000000
	index=0
	for pos in det_bit_pos_set:
		if det_bit_value_list[index]==1:
			pattern=spe_pattern_in_bit(pattern,pos,1)
		index=index+1
	return pattern,det_bit_pos_set

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
		best_pattern=pattern
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
					best_pattern=condidate_pattern_1

				if cur_match_num_0>max_match_num:
					max_match_num=cur_match_num_0
					max_bit_index=bit_index
					best_pattern=condidate_pattern_0
			bit_index=bit_index-1
		if max_match_num>0:	# 限定至少存在一种匹配方式，防止生成无效模式
			det_bit_set.add(max_bit_index)
			pattern=best_pattern

			# *******to remove*******************
			#print('max_bit_index',max_bit_index)
			#print('best_pattern','%#x'%pattern)
			# ***********************************

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
				#print(bit_index)
				pattern_1=spe_pattern_in_bit(pattern,bit_index,1) #设置为1
				#print('%#x'%pattern_1,'%#x'%pattern)
				iterate_gen_ipv6_scanning_list(pattern_1,det_bit_set,det_bit_num+1,bit_index-1,ipv6_scanning_list)
				iterate_gen_ipv6_scanning_list(pattern,det_bit_set,det_bit_num+1,bit_index-1,ipv6_scanning_list)
				break
			else:
				bit_index=bit_index-1

# 遍历前prefix_len位
def gen_ipv6_all_pattern(prefix_len):
	print('gen_ipv6_all_pattern')
	pattern=0x00000000000000000000000000000000
	for index in range(prefix_len):
		s_pattern=(spe_pattern_in_bit(pattern,index,1)) #将特定位设置为1
		det_bit_set_1=set()
		det_bit_set_1.add(index)
		det_bit_set_0=set()
		det_bit_set_0.add(index)
		iterate_pattern(s_pattern,1,det_bit_set_1)
		iterate_pattern(pattern,1,det_bit_set_0) #

# 先提取ipv6地址中确定位，再遍历前prefix_len位，优化模式生成算法
def improve_gen_ipv6_all_pattern(prefix_len):
	print('improve_gen_ipv6_all_pattern')
	pattern,det_bit_pos_set=get_determine_bit()
	det_bit_num=len(det_bit_pos_set)
	iterate_flag=False

	# *******TO REMOVE****************
	#print('origin pattern:','%#x'%pattern)
	#for x in det_bit_pos_set:
		#print(x,end=' ')
	#print(' ')
	# *********************************

	for index in range(prefix_len):
		if index not in det_bit_pos_set:
			iterate_flag=True
			s_pattern=(spe_pattern_in_bit(pattern,index,1)) #将特定位设置为1
			det_bit_set_1=det_bit_pos_set.copy()
			det_bit_set_1.add(index)
			det_bit_set_0=det_bit_pos_set.copy()
			det_bit_set_0.add(index)
			iterate_pattern(s_pattern,det_bit_num+1,det_bit_set_1)
			iterate_pattern(pattern,det_bit_num+1,det_bit_set_0) #将特定位设置为0
	if iterate_flag==False:
		iterate_pattern(pattern,det_bit_num,det_bit_pos_set)

# 参数：Ipv6模式 确定位集合
def gen_ipv6_scanning_list(pattern,det_bit_set):
	ipv6_scanning_list=[]
	iterate_gen_ipv6_scanning_list(pattern,det_bit_set,len(det_bit_set),ipv6_width-1,ipv6_scanning_list)
	return ipv6_scanning_list

def gen_ipv6_all_scanning_list():
	for pattern in pattern_det_bit_set.keys():
		ipv6_scanning_list_dict[pattern]=gen_ipv6_scanning_list(pattern,pattern_det_bit_set[pattern])

def merge_ipv6_scanning_list():
	ipv6_scanning_list=set()
	for ipv6_list in ipv6_scanning_list_dict.values():
		print('ipv6_list:',len(ipv6_list))
		for ipv6 in ipv6_list:
			ipv6_scanning_list.add(ipv6)
	return ipv6_scanning_list 

def measure_ipv6_scanning_list_accuracy():
	ipv6_scanning_list=merge_ipv6_scanning_list()
	match_num=0
	for ipv6 in ipv6_scanning_list:
		if ipv6 in test_ipv6_list:
			match_num=match_num+1
	print('ipv6_scanning_list num:',len(ipv6_scanning_list))
	print('test_ipv6_list:',len(test_ipv6_list))
	accuracy=match_num/len(ipv6_scanning_list)
	print('match_num:',match_num)
	print('accuracy:',accuracy)


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
		print('pattern:')
		print_16(pattern)
		print_16_list(ipv6_scanning_list_dict[pattern])
		print(len(ipv6_scanning_list_dict[pattern]))

def test_time():
	time_now=datetime.datetime.now().strftime('%H:%M:%S.%f')
	print(time_now)
	last_time=time.time()
	for i in range(10000000):
		i=i+1
	cur_time=time.time()
	print(cur_time-last_time)

def test_get_determine_bit():
	pattern,det_bit_pos_set=get_determine_bit()
	print(len(det_bit_pos_set))
	print_16(pattern)
	for x in det_bit_pos_set:
		print(x,end=' ')
	print(' ')

if __name__=='__main__':
	
	last_time=time.time()
	print('determined_num:',threshold)
	print('start_prefix_len:',start_prefix_len)

	# 产生全体测试集
	#gen_all_testdata_txt('D:/DataSet/responsive-addresses/responsive-addresses.txt')


	#read_write_data_fromin_txt('D:/DataSet/responsive-addresses/responsive-addresses.txt',12,10)
	# 产生训练集
	start_point=10000
	train_num=10000
	gen_train_data_txt('D:/DataSet/responsive-addresses/responsive-addresses.txt',start_point,train_num)
	print('start_point:',start_point)
	print('train_num:',train_num)
	
	# 读取训练集
	read_ipv6_from_32_16_txt(train_ipv6_list,'D:/DataSet/responsive-addresses/responsive-addresses-trainnum.txt')
	#test_get_determine_bit()
	read_ipv6_from_32_16_txt_gen_set(test_ipv6_list,'D:/DataSet/responsive-addresses/responsive-addresses-testall.txt')
	# baseline algorithm(paper)
	#gen_ipv6_all_pattern(start_prefix_len)
	# improved algorithm
	improve_gen_ipv6_all_pattern(start_prefix_len)
	print_pattern_det_bit_set()
	gen_ipv6_all_scanning_list()
	#print_ipv6_scanning_list_dict()b
	measure_ipv6_scanning_list_accuracy()
	cur_time=time.time()

	print('running time:',cur_time-last_time)
	#ipv6_scan_gen_test()

