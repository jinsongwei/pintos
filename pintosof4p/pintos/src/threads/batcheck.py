#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#       未命名.py
#       
#       Copyright 2010 mayli <mayli.he@gmail.com>
#       
#       This program is free software; you can redistribute it and/or modify
#       it under the terms of the GNU General Public License as published by
#       the Free Software Foundation; either version 2 of the License, or
#       (at your option) any later version.
#       
#       This program is distributed in the hope that it will be useful,
#       but WITHOUT ANY WARRANTY; without even the implied warranty of
#       MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#       GNU General Public License for more details.
#       
#       You should have received a copy of the GNU General Public License
#       along with this program; if not, write to the Free Software
#       Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#       MA 02110-1301, USA.
import re
import os
import random

iter = 10

def main():
  #~ os.system("mkdir 1;mkdir 2;mkdir 3;mkdir 4");
  #~ os.system('rm 1/*;rm 2/*;rm 3/*;rm 4/*')
  #~ checks = ['make check','make check PINTOSOPIS=-j ','make check PINTOSOPIS=-r','make check SIMULATOR=--qemu']
  #~ os.system('make clean')
  #~ for i in range(0,1):
    #~ for j in range(0,iter):
      #~ os.system("rm -r build/*")
      #~ if i==1:
        #~ os.system(checks[i]+"%d"%random.randint(1,10))
      #~ else:
        #~ os.system(checks[i])
      #~ os.system("cat build/results >> ./%d/res"%(i+1))
  #~ 
  rpass =re.compile('(pass) tests/threads/(.*)')
  #~ 
  for i in range(0,4):
    stat = {}
    f=file('./%d/res'%(i+1))
    text=f.read()
    res = rpass.findall(text)
    for r in res:
      if(stat.has_key(r[1])):
        stat[r[1]] +=  1
      else:
        stat[r[1]] = 1
    statf=file('./%d/stat'%(i+1),'w')
    for key in stat.keys():
      statf.write("%s %0.1f%%\n"%(key,stat[key]*100/iter))
    print stat
    #print res
    f.close()
    statf.close()
  return 0

if __name__ == '__main__':
  main()
