#!/usr/bin/python
# -*- coding: utf-8 -*-

# function@generate ipv6 patterns
# time@2018-12-4
# author@kuangp  

# ipv6 standard format:0x1111222233334444555566667777ffff

import xlrd
import csv

raw_ipv6_list=[]
format_ipv6_list=[]
threshold=100 # maximal undetermined bit num,global variable
pattern_list=[]
best_pattern_num=10
char_set={'0':0,'1':1,'2':2,'3':3,'4':4,'5':5,'6':6,'7':7,'8':8,'9':9
,'a':10,'b':11,'c':12,'d':13,'e':14,'f':15}
digit_set={"10":'a',"11":'b',"12":'c',"13":'d',"14":'e',"15":'f'}
num_set={0:'0',1:'1',2:'2',3:'3',4:'4',5:'5','0':0,'6':6,7:'7',8:'8',9:'9'
,10:'a',11:'b',12:'c',13:'d',14:'e',15:'f'}

class PatternCount:
	def __init__(self,pattern,count):
		self.pattern=pattern
		self.count=count
	def display(self):
		print('pattern:',pattern,'count:',count)
	def set(self,pattern,count):
		self.pattern=pattern
		self.count=count
	def get_pattern():
		return self.pattern
	def get_count():
		return self.count

def print_list(value_list):
	for x in value_list:
		print('%#x'%x)

# func: ipv6 address formulate, remove duplicate ipv6 address
# input: ipv6 address txt file path
# output: generate a formatting ipv6 address file
def read_write_data_fromin_txt(path):

	f=open(path,'r')
	path_seg=path.split('.')
	testpath=path_seg[0]+'-test'+'.txt'
	trainpath=path_seg[0]+'-train'+'.txt'
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

	ipv6_dict_keys=ipv6_dict.keys()
	index=0
	for x in ipv6_dict_keys:
		if index<7:
			train.writelines(x+'\n')
		else:
			test.writelines(x+'\n')
		index=(index+1)%10
	f.close()
	test.close()
	train.close()

def read_data_from_txt(path):
	f=open(path,'r')
	line=f.readline()
	line=line[:-1]
	# ignore first line
	while line:
		line=f.readline()
		line=line[:-1]
		raw_ipv6_list.append(line)
	f.close()
	
def read_data_from_excel(path,sheet_name,col):
	data=xlrd.open_workbook('alexa1m-2017-04-03.csv')
	table=data.seet_by_name('alexa1m-2017-04-03')
	raw_ipv6_list=table.col_values(col)

def read_data_from_csv(path,col):
	with open(path,'r') as csvfile:
		reader=csv.reader(csvfile)
		for row in reader:
			raw_ipv6_list.append(row[col])
		#raw_ipv6_list=[row[col] for row in reader]

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

def standard_ipv6_gen():
	for x in raw_ipv6_list:
		format_ipv6_list.append(ipv6_formate(x))

# mode: front to end, end to front, edge to middle
def do_recursion_with(pattern,undetermined_num,mode):
	if undetermined_num<=threshold:
		pattern_list.append(pattern)
	else:
		#print("pattern:",'%#x'%pattern)
		bit=determine_next_bit(pattern,undetermined_num,mode);
		#pattern=apply(pattern,mode,bit)
		if mode==1:
			pattern=pattern>>(undetermined_num-1)
			pattern=pattern|bit
			pattern=pattern<<(undetermined_num-1)
		do_recursion_with(pattern,undetermined_num-1,mode)
		#inverse_bit=(bit^1)
		#inverse_pattern=apply(pattern,mode,inverse_bit)
		#do_recursion_with(inverse_pattern,undetermined_num-1,mode)

def determine_next_bit(pattern,undetermined_num,mode): 
	if mode==1:	# from front to end
		num_1=0
		num_0=0
		bit=0
		pattern=pattern>>undetermined_num
		for ipv6 in format_ipv6_list:
			ipv6=ipv6>>(undetermined_num-1)
			bit=ipv6&1
			ipv6=ipv6>>1
			#print("pattern:",pattern,"ipv6:",ipv6)
			if pattern==ipv6:
				if bit==1:
					num_1=num_1+1
				else:
					num_0=num_0+1
			#print("num_1:",num_1,"num_0:",num_0)
		if num_1>=num_0:
			return 1
		else:
			return 0

# threshold: undetermined bit num
def generate_ipv6_pattern():
	# mode 1
	pattern=0x00000000000000000000000000000000
	do_recursion_with(pattern,127,1)

	# mode 2

	# mode 3

def print_pattern():
	for pattern in pattern_list:
		print('%#x'%pattern)


res_ipv6_list=[]

# parm: @ipv6_pattern: determined bit and undetermined bit(x)
def gen_ipv6_scanning_list(ipv6_pattern):
	length=len(ipv6_pattern)-1
	iterate_ipv6(ipv6_pattern,0,length)
	for x in res_ipv6_list:
		print(x)
	

def iterate_ipv6(iterate_ipv6_pattern,pos,length):
	if pos>length:
		res_ipv6_list.append(iterate_ipv6_pattern)
	else:
		while iterate_ipv6_pattern[pos]!='x' and pos<length:
			pos=pos+1
		if pos>length:
			res_ipv6_list.append(iterate_ipv6_pattern)
		else:
			pattern_1=list(iterate_ipv6_pattern)
			pattern_1[pos]='1'
			iterate_ipv6(''.join(pattern_1),pos+1,length)
			pattern_0=list(iterate_ipv6_pattern)
			pattern_0[pos]='0'
			iterate_ipv6(''.join(pattern_0),pos+1,length)



	
def select_best_no_pattern(pattern_num):
	# use queue maintainig quantity
	determine_bit=0
	pattern=''

if __name__=='__main__':

	#read_data_from_excel('D:/DataSet/alexa1m-2017-04-03.csv/alexa1m-2017-04-03.csv','alexa1m-2017-04-03',0)
	#read_data_from_excel('alexa1m-2017-04-03.csv','alexa1m-2017-04-03',0)
	read_write_data_fromin_txt('D:/DataSet/responsive-addresses/responsive-addresses.txt')

	#read_data_from_csv('D:/DataSet/alexa1m-2017-04-03.csv/alexa1m-2017-04-03.csv',0)
	

	#read_data_from_txt('D:/DataSet/responsive-addresses/responsive-addresses.txt')
	#print_list(raw_ipv6_list)
	#standard_ipv6_gen()

	#print_list(format_ipv6_list)
	
	#format_ipv6_list.append(0xe111222233334444555566667777ffff)
	#format_ipv6_list.append(0xe1112222333344445555666677771fff)
	#format_ipv6_list.append(0xe111222233334444555566667777ffff)

	#print(ipv6_formate("2c0f:fec8:16::38:255.255.255.255"))

	#generate_ipv6_pattern()
	#print_pattern()

	gen_ipv6_scanning_list('00xx000000')





