#!/usr/bin/env python3

code0 = open('code0.dat')
code1 = open('code1.dat')
for line in code0:
	print(line.rstrip())
	print(code1.readline().rstrip())
