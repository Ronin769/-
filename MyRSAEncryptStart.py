# coding:UTF-8
#MyRSA.py
#author:Kevinhanser

import wx
import os
import time
import pickle
import socket
import threading
import random, sys
import select
import queue as Queue
from makeRsaKeys import makeKeyFiles
from rsaCipher import encript, decript



#reload(sys)
#sys.setdefaultencoding('utf8')

#wildcard = "Sketch files (*.sketch)|*.sketch|All files (*.*)|*.*"
wildcard1 = u" w文本文件 (*.exc)|*.exc|"    \
           "All files (*.*)|*.*"
wildcard2 = u" w文本文件 (*.pem)|*.pem|"    \
           "All files (*.*)|*.*"
fileDir = os.getcwd()

class MultiTextFrame(wx.Frame):
    def __init__(self):
        wx.Frame.__init__(self, None, -1, u"基于 Python 的安全传输工具 V1.5",
                          size=(600, 550))

        global filepath1, filepath2, panel, keysize, publicKey, privateKey, hostip
        keysize = 0
        fileDir = os.getcwd()

        '''创建菜单'''
        menuBar = wx.MenuBar()      #创建一个 菜单栏
        #创建一个“keyfilemenu”菜单
        keyfilemenu= wx.Menu()
        menuPubkeyfile = keyfilemenu.Append(wx.ID_OPEN, u"&打开公钥文件")
        menuPrikeyfile = keyfilemenu.Append(wx.ID_ANY, u"&打开私钥文件")
        menuBar.Append(keyfilemenu,u"&打开密钥文件") # Adding the "filemenu" to the MenuBar
        #创建一个“acmkeymenu”菜单
        acmkeymenu = wx.Menu()
        menuAcmkey = acmkeymenu.Append(wx.ID_ANY, u"&生成公私钥对")
        menuBar.Append(acmkeymenu,u"&生成密钥文件") # Adding the "filemenu" to the MenuBar
        #创建一个“aboutmenu”菜单
        aboutmenu = wx.Menu()
        menuAbout= aboutmenu.Append(wx.ID_ABOUT, u"&关于这个软件")
        menuBar.Append(aboutmenu,u"&关于")
        #创建一个“helpmenu”菜单
        helpmenu = wx.Menu()
        menuHelp = helpmenu.Append(wx.ID_HELP,u"&我能做什么？")
        menuBar.Append(helpmenu,u"&帮助")
        self.SetMenuBar(menuBar)  # Adding the MenuBar to the Frame content.
        #创建一个“exitmenu”菜单
        exitmenu = wx.Menu()
        menuExit = exitmenu.Append(wx.ID_EXIT,u"&退出程序")
        menuBar.Append(exitmenu,u"&退出")
        #创建一个“resetmenu”菜单
        resetmenu = wx.Menu()
        menuReset = resetmenu.Append(wx.ID_RESET,u"&重置此程序")
        menuBar.Append(resetmenu,u"&重置")

        '''面板设计'''
        panel = wx.Panel(self, -1)
        #panel.SetBackgroundColour('#c0c3c8')
        #font = wx.SystemSettings_GetFont(wx.SYS_SYSTEM_FONT)
        font = wx.Font(9, wx.ROMAN, wx.NORMAL, wx.BOLD, False)
        fontbt = wx.Font(9, wx.ROMAN, wx.NORMAL, wx.BOLD, False)
        fontms = wx.Font(8, wx.ROMAN, wx.NORMAL, wx.NORMAL, False)
        font.SetPointSize(9)

        #vbox：纵向排列的容器
        vbox = wx.BoxSizer(wx.VERTICAL)

        vbox.Add((-1, 5))  #预留15像素空白,vbox6此行开始






        #st7:“端口”
        hbox8 = wx.BoxSizer(wx.HORIZONTAL)
        
        #st7 = wx.StaticText(panel, 0, label=u'端口', style=wx.TE_LEFT)
        #st7.SetFont(font)
        #hbox8.Add(st7,proportion=0,flag=wx.LEFT,border = 15)    #静态文本的左右空间15

        #PortText: 端口
        #self.PortText = wx.TextCtrl(panel, value="8181",size=(60,30))
        #hbox8.Add(self.PortText,proportion=1,flag=wx.ALIGN_LEFT)


        #st5：“服务器IP”
        #st5 = wx.StaticText(panel, 0, label=u'服务器IP', style=wx.TE_LEFT) #静态文本
        #st5.SetFont(font)
        #hbox8.Add(st5,proportion=0,flag=wx.LEFT,border = 15)    #静态文本的左右空间15
        
        #ipaddr: IP地址栏
        #myname = socket.getfqdn(socket.gethostname())
        #myaddr = socket.gethostbyname(myname)
        #self.ipaddr = wx.TextCtrl(panel, value="172.16.10.131",size=(1024,30))
        #hbox8.Add(self.ipaddr,proportion=1,flag=wx.ALIGN_LEFT)

            
        #btn7：“作为服务器”
        self.btn7 = wx.Button(panel, label=u'作为服务器登录', size=(150, 30))
        self.btn7.SetFont(fontbt)
        hbox8.Add(self.btn7,proportion=0,flag=wx.RIGHT|wx.LEFT, border=15)    #按钮7的左右空间15
        #btn8：“作为客户端”
        self.btn8 = wx.Button(panel, label=u'作为客户端登录', size=(150, 30))
        self.btn8.SetFont(fontbt)
        hbox8.Add(self.btn8,proportion=0,flag=wx.RIGHT|wx.LEFT, border=15)    #按钮8的左右空间15



         #sendButton: 发送密文
        self.sendButton = wx.Button(panel, label=u'向服务器发送密文', size=(150, 30))
        self.sendButton.SetFont(fontbt)
        hbox8.Add(self.sendButton,proportion=0,flag=wx.RIGHT|wx.LEFT, border=15)    #按钮sendButton的左右空间15

        #recvButton: 接收密文
        #self.recvButton = wx.Button(panel, label=u'接收密文', size=(80, 30))
        #self.recvButton.SetFont(fontbt)
        #hbox8.Add(self.recvButton,proportion=0,flag=wx.RIGHT|wx.LEFT, border=5)    #按钮3的左右空间15

        
        vbox.Add(hbox8, proportion=1, flag= wx.ALIGN_CENTER_VERTICAL)    #三部分水平分布
        vbox.Add((-1, 5))  #预留15像素空白


        hbox7 = wx.BoxSizer(wx.HORIZONTAL)
        #st6：“信息框”
        st6 = wx.StaticText(panel, label=u'信息框')
        st6.SetFont(font)
        hbox7.Add(st6,flag=wx.RIGHT, border=10) #密文区域左空间
        #tc3：信息框内容
        self.tc3 = wx.TextCtrl(panel, size=(400,150),style=wx.TE_MULTILINE | wx.TE_RICH2) # wx.HSCROLL 不自动换行
        self.tc3.SetFont(fontms)
        hbox7.Add(self.tc3, proportion=1, flag=wx.EXPAND)
        vbox.Add(hbox7, proportion=1, flag=wx.LEFT | wx.RIGHT |wx.BOTTOM| wx.EXPAND,border=10)    #密文区域右空间





        #st3：明文文件
        hbox6 = wx.BoxSizer(wx.HORIZONTAL)
        st3 = wx.StaticText(panel, 0, label=u'明文文件：', style=wx.TE_LEFT) #静态文本
        st3.SetFont(font)
        hbox6.Add(st3,proportion=0,flag=wx.LEFT|wx.RIGHT,border = 15)    #静态文本的左右空间15
        #filepath1: 明文路径
        filepath1 = wx.TextCtrl(panel, size=(1024,30))
        hbox6.Add(filepath1,proportion=1,flag=wx.ALIGN_LEFT)
        #btn3：“浏览上”
        btn3 = wx.Button(panel, label=u'浏览', size=(70, 30))
        btn3.SetFont(fontbt)
        hbox6.Add(btn3,proportion=0,flag=wx.RIGHT|wx.LEFT, border=15)    #按钮3的左右空间15
        #btn4：“保存上”
        btn4 = wx.Button(panel, label=u'另存为', size=(70, 30))
        btn4.SetFont(fontbt)
        hbox6.Add(btn4,proportion=0,flag=wx.RIGHT|wx.LEFT, border=15)    #按钮3的左右空间15
        vbox.Add(hbox6, proportion=1,flag= wx.BOTTOM|wx.ALIGN_CENTER_VERTICAL,border=0)    #三部分水平分布

        vbox.Add((-1, 5))  #预留15像素空白

        #st1：“明文”
        hbox1 = wx.BoxSizer(wx.HORIZONTAL)
        st1 = wx.StaticText(panel, label=u'明文') #静态文本
        st1.SetFont(font)

        #tc1: 明文文本框内容
        hbox1.Add(st1, flag=wx.RIGHT, border=10)    #明文区域左空间
        self.tc1 = wx.TextCtrl(panel,size=(400,80),style=wx.TE_MULTILINE | wx.TE_RICH2 )
        self.tc1.SetFont(font)
        hbox1.Add(self.tc1, proportion=1, flag=wx.EXPAND)
        vbox.Add(hbox1, proportion=1, flag=wx.LEFT | wx.RIGHT | wx.EXPAND, border=10)   #明文区域右空间

        vbox.Add((-1, 5))  #预留15像素空白

        #st4：“密文文件：”
        hbox6 = wx.BoxSizer(wx.HORIZONTAL)
        st4 = wx.StaticText(panel, 0, label=u'密文文件：', style=wx.TE_LEFT) #静态文本
        st4.SetFont(font)
        hbox6.Add(st4,proportion=0,flag=wx.LEFT|wx.RIGHT,border = 15)    #静态文本的左右空间15
        #filepath2: 密文路径
        filepath2 = wx.TextCtrl(panel, size=(1024,30))
        hbox6.Add(filepath2,proportion=1,flag=wx.ALIGN_LEFT)
        #btn5：“浏览下””
        btn5 = wx.Button(panel, label=u'浏览', size=(70, 30))
        btn5.SetFont(fontbt)
        hbox6.Add(btn5,proportion=0,flag=wx.RIGHT|wx.LEFT, border=15)    #按钮3的左右空间15
        #btn6：“保存下”
        btn6 = wx.Button(panel, label=u'另存为', size=(70, 30))
        btn6.SetFont(fontbt)
        hbox6.Add(btn6,proportion=0,flag=wx.RIGHT|wx.LEFT, border=15)    #按钮3的左右空间15
        vbox.Add(hbox6, proportion=1, flag= wx.ALIGN_CENTER_VERTICAL)    #三部分水平分布
        vbox.Add((-1, 15))  #预留15像素空白

        hbox3 = wx.BoxSizer(wx.HORIZONTAL)
        #st2：“密文”
        st2 = wx.StaticText(panel, label=u'密文')
        st2.SetFont(font)

        hbox3.Add(st2,flag=wx.RIGHT, border=10) #密文区域左空间
        #tc2：密文文本框内容
        self.tc2 = wx.TextCtrl(panel, size=(400,80),style=wx.TE_MULTILINE | wx.TE_RICH2 | wx.TE_READONLY) # wx.HSCROLL 不自动换行
        self.tc2.SetFont(font)
        hbox3.Add(self.tc2, proportion=1, flag=wx.EXPAND)
        vbox.Add(hbox3, proportion=1, flag=wx.LEFT | wx.RIGHT |wx.BOTTOM| wx.EXPAND,border=10)    #密文区域右空间




        hbox5 = wx.BoxSizer(wx.HORIZONTAL)
        #btn1:"RSA加密"
        btn1 = wx.Button(panel, label=u'RSA加密', size=(110, 30))
        btn1.SetFont(font)
        hbox5.Add(btn1)
        #btn2：“RSA解密”
        btn2 = wx.Button(panel, label=u'RSA解密', size=(110, 30))
        btn2.SetFont(font)
        hbox5.Add(btn2, flag=wx.LEFT , border=50)    #两个按钮中间空间
        vbox.Add(hbox5, flag=wx.ALIGN_CENTER_HORIZONTAL, border=30) #两个按钮右空间
        vbox.Add((-1, 15))  #预留15像素空白

        panel.SetSizer(vbox)

        '''绑定事件'''
        '''
        #st1：“明文”
        #st2：“密文”
        #st3：明文文件
        #st4：“密文文件：”
        #st5：“服务器IP”
        #st6：“信息框”
        
        #ipaddr: IP地址栏
        #filepath1: 明文路径
        #filepath2: 密文路径

        #btn1:"RSA加密"
        #btn2：“RSA解密”
        #btn3：“浏览上”
        #btn4：“保存上”
        #btn5：“浏览下”
        #btn6：“保存下”
        #btn7：“作为服务器”
        #btn8：“作为客户端”

        #tc: 明文文本框内容
        #tc2：密文文本框内容
        #tc3：信息框内容

        #menuPubkeyfile: 打开公钥文件
        #menuPrikeyfile：打开私钥文件
        #menuPubkey：计算一个公钥
        #menuPrikey：计算一个私钥
        #menuAbout：关于这个软件
        #menuExit：退出程序
        #menuHelp：我能做什么？
        #menuReset: 重置此程序
        '''

        self.Bind(wx.EVT_BUTTON, self.encryptMessage, btn1)
        self.Bind(wx.EVT_BUTTON, self.decryptMessage, btn2)
        self.Bind(wx.EVT_BUTTON, self.openplaintextfile, btn3)
        self.Bind(wx.EVT_BUTTON, self.saveplaintextfile, btn4)
        self.Bind(wx.EVT_BUTTON, self.openciphertextfile, btn5)
        self.Bind(wx.EVT_BUTTON, self.saveciphertextfile, btn6)
        self.Bind(wx.EVT_BUTTON, self.OnSeverClick, self.btn7)
        self.Bind(wx.EVT_BUTTON, self.OnClientClick, self.btn8)
        self.Bind(wx.EVT_BUTTON, self.OnSendClick, self.sendButton)
        #self.Bind(wx.EVT_BUTTON, self.OnRecvClick, self.recvButton)


        

        self.Bind(wx.EVT_MENU, self.openpubfile, menuPubkeyfile)
        self.Bind(wx.EVT_MENU, self.openprifile, menuPrikeyfile)
        self.Bind(wx.EVT_MENU, self.accountkeyfile, menuAcmkey)
        self.Bind(wx.EVT_MENU, self.OnAbout, menuAbout)
        self.Bind(wx.EVT_MENU, self.OnExit, menuExit)
        self.Bind(wx.EVT_MENU, self.OnHelp, menuHelp)
        self.Bind(wx.EVT_MENU, self.OnReset, menuReset)


    '''函数开始'''


    def encryptMessage(self, event):      
        '''
        加密文件内容，并清空密文文本框
        '''
        #self.tc1.Clear()
        self.tc2.Clear()    #点2次关闭
        num = 0 #输入的汉字个数
        tc1data = self.tc1.GetValue()
        for ch in tc1data:
            if u'\u4e00' <= ch <= u'\u9fff':
                num += 1
                break
        if num > 0:
            self.messagedata = '文本框内容禁止输入中文！\n请重新输入：'
            print(self.messagedata)
            self.tc3.AppendText('\n%s' % self.messagedata)
            dlg = wx.MessageDialog(self, self.messagedata, caption='提示：', style = wx.OK|wx.ICON_EXCLAMATION)
            dlg.ShowModal()
            
        else:
            if tc1data != '':



                dlg5 = wx.FileDialog(
                    self,defaultFile="file_pubkey.pem",
                    message=u"请选择加密要使用的公钥文件...",
                    defaultDir=fileDir,
                    wildcard=wildcard2,
                    style=wx.FD_OPEN | wx.FD_MULTIPLE)
                if dlg5.ShowModal() == wx.ID_OK:
                    pubkeyfilename5 = dlg5.GetPath()

                    self.tc2.AppendText(encript(tc1data,pubkeyfilename5))
                    print('明文已成功加密并已输出到密文框，可以将密文信息发送至服务器...')
                    self.tc3.AppendText('明文已成功加密并已输出到密文框，可以将密文信息发送至服务器...')
                    self.messagedata = '明文已成功加密并已输出到密文框！\n未防止信息丢失，请将信息保存到文件！'
                    dlg = wx.MessageDialog(self, self.messagedata, caption='加密模块', style = wx.OK|wx.ICON_AUTH_NEEDED)
                    dlg.ShowModal()
                    
            else:
                self.messagedata = '明文文本框内容为空！\n请输入明文或选择明文文件：'
                print('明文文本框内容为空！')
                self.tc3.AppendText('\n明文文本框内容为空！')
                dlg = wx.MessageDialog(self, self.messagedata, caption='明文', style = wx.OK|wx.ICON_HAND)
                dlg.ShowModal()
                


    def decryptMessage(self, event):
        '''
        解密文件内容，并清空明文文本框
        '''
        self.tc1.Clear()
        #self.tc2.Clear()
        tc2data = self.tc2.GetValue()
        if tc2data != '':




            dlg6 = wx.FileDialog(
                    self,defaultFile="file_privkey.pem",
                    message=u"请选择解密要使用的私钥文件...",
                    defaultDir=fileDir,
                    wildcard=wildcard2,
                    style=wx.FD_OPEN | wx.FD_MULTIPLE)
            if dlg6.ShowModal() == wx.ID_OK:
                
                if os.path.exists(dlg6.GetPath()) == True:
                    pubkeyfilename6 = dlg6.GetPath()
                    self.tc1.AppendText(decript(tc2data,pubkeyfilename6))
                    print('密文已成功解密并输出到明文框')
                    self.tc3.AppendText('\n密文已成功解密并输出到明文框')
                    self.messagedata = '密文已成功解密并输出到明文框！\n未防止信息丢失，请将信息保存到文件！'
                    dlg = wx.MessageDialog(self, self.messagedata, caption='解密模块', style = wx.OK|wx.ICON_AUTH_NEEDED)
                    dlg.ShowModal()
                    
                else:
                    dlg = wx.MessageDialog(self,'您选择的私钥文件不存在，请重新选择私钥文件！', caption='私钥文件不存在', style = wx.OK|wx.ICON_ERROR)
                    dlg.ShowModal()
                    
                
        else:
            self.messagedata = '密文文本框内容为空！\n请选择密文文件或先进行消息加密：'
            dlg = wx.MessageDialog(self, self.messagedata, caption='明文', style = wx.OK|wx.ICON_HAND)
            dlg.ShowModal()


    def openplaintextfile(self, event):
        dlg = wx.FileDialog(
            self,defaultFile="message.exc",
            message=u"选择所要加密的明文文件",
            defaultDir=fileDir,
            wildcard=wildcard1,
            style=wx.FD_OPEN | wx.FD_MULTIPLE)
        dlg.SetDirectory(fileDir)
        if dlg.ShowModal() == wx.ID_OK:
            tmp=""
            #paths = dlg.GetPaths()
            paths = dlg.GetPaths()
            #print "You chose the following file(s):"
            for path in paths:
                tmp=tmp+path
            #set the value of TextCtrl[filepath1]
            filepath1.SetValue(tmp)
            #set the value to the TextCtrl[tc1]
            file=open(filepath1.GetValue())
            self.tc1.SetValue(file.read())
            file.close()
            print('明文文件打开成功！')
            self.tc3.AppendText('\n明文文件打开成功！')
        
        dlg.Destroy()


    def saveplaintextfile(self,event):
        """
        Create and show the Save FileDialog
        """
        content = self.tc1.GetValue()
        if content != '':
            dlg = wx.FileDialog(self,
                                message=u"将已加密的数据另存为：",
                                defaultDir=fileDir,
                                defaultFile="message.exc",
                                wildcard=wildcard1,
                                style=wx.FD_SAVE|wx.FD_OVERWRITE_PROMPT
                                 )


            
            if dlg.ShowModal() == wx.ID_OK:
                filename=""
                paths = dlg.GetPaths()
                #split the paths
                for path in paths:
                    filename=filename+path

                #paths:['C:\\Users\\John\\Desktop\\pythonwork V2.0\\encrypted_file.exc']
                #filename:C:\Users\John\Desktop\pythonwork V2.0\encrypted_file.exc
                #filename2 = filename.split('\\') #filename2:文件名，filename:文件路径及文件名
                #global plainfilerename
                #filerename = filename2[-1]
                    
                #write the contents of the TextCtrl[self.tc1] into the file
                #print(paths)
                
                
                filename.encode(encoding='UTF-8',errors='strict')
                file=open(filename,'w')
                file.write(content)
                file.close()
                print('另存为明文文件成功！')
                self.tc3.AppendText('\n另存为明文文件成功！')
                dlg = wx.MessageDialog(self, u"另存为明文文件成功！", u"文本状态", wx.OK | wx.ICON_INFORMATION)
                dlg.ShowModal() # Shows it
                #show the save file path
                filepath1.SetValue(filename)
            dlg.Destroy()
        else:
            print('明文文本框为空!')
            self.tc3.AppendText('\n明文文本框为空!')
            dlg = wx.MessageDialog(self, u"明文文本框为空！\n请选择明文文件！", u"文本状态", wx.OK | wx.ICON_ERROR)
            dlg.ShowModal() # Shows it
            dlg.Destroy() # finally destroy it when finished.
    


    def openciphertextfile(self,event):
        dlg = wx.FileDialog(
            self,defaultFile="encrypted_file.exc",
            message=u"选择所要解密的密文文件",
            defaultDir=fileDir,
            wildcard=wildcard1,
            style=wx.FD_OPEN | wx.FD_MULTIPLE)
        if dlg.ShowModal() == wx.ID_OK:
            tmp=""
            #paths = dlg.GetPaths()
            paths = dlg.GetPaths()
            #print "You chose the following file(s):"
            for path in paths:
                tmp=tmp+path
            #set the value of TextCtrl[filepath2]
            filepath2.SetValue(tmp)
            #set the value to the TextCtrl[tc2]
            file=open(filepath2.GetValue())
            self.tc2.SetValue(file.read())
            file.close()
            print('打开密文文件成功！')
            self.tc3.AppendText('\n打开密文文件成功！')
        dlg.Destroy()


    def saveciphertextfile(self,event):
        """
        Create and show the Save FileDialog
        """
        content = self.tc2.GetValue()
        if content != '':
            dlg = wx.FileDialog(self,
                                message=u"将已解密的数据另存为：",
                                defaultDir=fileDir,
                                defaultFile="encrypted_file.exc",
                                wildcard=wildcard1,
                                style=wx.FD_SAVE|wx.FD_OVERWRITE_PROMPT
                                )
            if dlg.ShowModal() == wx.ID_OK:
                filename=""
                paths = dlg.GetPaths()
                #split the paths
                for path in paths:
                    filename=filename+path
                
                #paths:['C:\\Users\\John\\Desktop\\pythonwork V2.0\\encrypted_file.exc']
                #filename:C:\Users\John\Desktop\pythonwork V2.0\encrypted_file.exc
                #filename2 = filename.split('\\') #filename2:文件名，filename:文件路径及文件名
                #global cipherfilerename
                #filerename = filename2[-1]
                
                #write the contents of the TextCtrl[self.tc1] into the file
                filename.encode(encoding='UTF-8',errors='strict')
                file=open(filename,'w')
                file.write(self.tc2.GetValue())
                file.close()
                print('另存为密文文件成功！')
                self.tc3.AppendText('\n另存为密文文件成功！')
                dlg = wx.MessageDialog(self, u"另存为密文文件成功！", u"文本状态", wx.OK | wx.ICON_INFORMATION)
                dlg.ShowModal() # Shows it
                #show the save file path
                filepath2.SetValue(filename)
            dlg.Destroy()
        else:
            print('密文文本框为空！')
            self.tc3.AppendText('\n密文文本框为空！')
            dlg = wx.MessageDialog(self, u"密文文本框为空！\n请选择密文文件！", u"文本状态", wx.OK | wx.ICON_ERROR)
            dlg.ShowModal() # Shows it
            dlg.Destroy() # finally destroy it when finished.

    def openpubfile(self,event):

        dlg1 = wx.FileDialog(
            self,defaultFile="file_privkey.pem",
            message=u"选择要读取得公钥文件名：",
            defaultDir=fileDir,
            wildcard=wildcard2,
            style=wx.FD_OPEN | wx.FD_MULTIPLE)
        if dlg1.ShowModal() == wx.ID_OK:
            self.pubfilename = dlg1.GetPath()

            self.pubfilename = 'file_pubkey.pem'
            if os.path.exists(self.pubfilename) == True:
                fo = open(self.pubfilename)
                self.pubkeyfiledata = fo.read()
                fo.close()
                self.spam= []
                #count = 0
                self.pubkeylist = list(self.pubkeyfiledata)
                #for i in self.pubkeylist:
                for num,i in enumerate(self.pubkeylist):
                    if num > 4:
                        self.spam.append(i)
                        #print(num)
                        if num % 67 == 1:
                            self.spam.append('\n')
                self.spam.append('\n')
                self.pubkeyfiledata = ''.join(self.spam)
                   
               #GenericMessageDialog （parent ， message ， caption  ，style  ， pos ）
                dlg = wx.GenericMessageDialog(self,"",caption="公钥文件数据", style=wx.OK|wx.ICON_INFORMATION)
                dlg.SetMessage("Public Key: \n%s" % (self.pubkeyfiledata))
                dlg.ShowModal()
                print('\n公钥文件读取成功！')
                self.tc3.AppendText('公钥文件读取成功！')
                dlg.Destroy() # finally destroy it when finished.
            else:
                print('\n公钥文件不存在！')
                self.tc3.AppendText('公钥文件不存在！')
                dlg = wx.MessageDialog(self, u"公钥文件不存在！\n请重新生成公钥文件!", u"文件状态", wx.OK | wx.ICON_ERROR)
                dlg.ShowModal() # Shows it
                dlg.Destroy() # finally destroy it when finished.
            
        
    def openprifile(self,event):


        dlg1 = wx.FileDialog(
            self,defaultFile="file_privkey.pem",
            message=u"选择要读取得公钥文件名：",
            defaultDir=fileDir,
            wildcard=wildcard2,
            style=wx.FD_OPEN | wx.FD_MULTIPLE)
        if dlg1.ShowModal() == wx.ID_OK:
            self.prifilename = dlg1.GetPath()

            #self.prifilename = 'file_privkey.pem'
            if os.path.exists(self.prifilename) == True:
                fo = open(self.prifilename)
                self.prikeyfiledata = fo.read()
                fo.close()
                self.spam= []
                #count = 0
                self.pubkeylist = list(self.prikeyfiledata)
                #for i in self.pubkeylist:
                for num,i in enumerate(self.pubkeylist):
                    if num > 4:
                        self.spam.append(i)
                        #print(num)
                        if num % 77 == 1:
                            self.spam.append('\n')
                self.spam.append('\n')
                self.prikeyfiledata = ''.join(self.spam)
                   
                #GenericMessageDialog （parent ， message ， caption  ，style  ， pos ）
                dlg = wx.GenericMessageDialog(self,"",caption="私钥文件数据", style=wx.OK|wx.ICON_INFORMATION)
                dlg.SetMessage("Private Key: \n%s" % (self.prikeyfiledata))
                dlg.ShowModal()
                print('私钥文件读取成功！')
                self.tc3.AppendText('\n私钥文件读取成功！')
                dlg.Destroy() # finally destroy it when finished.
            else:
                print('私钥文件不存在！')
                self.tc3.AppendText('\n私钥文件不存在！')
                dlg = wx.MessageDialog(self, u"私钥文件不存在！\n请重新生成私钥文件!", u"文件状态", wx.OK | wx.ICON_ERROR)
                dlg.ShowModal() # Shows it
                dlg.Destroy() # finally destroy it when finished.
            


    def accountkeyfile(self, event):
        dlg = wx.TextEntryDialog(self, u"请输入密钥大小(默认为1024位)：",u"加密密钥位数对话框", u"1024")
        if dlg.ShowModal() == wx.ID_OK:
            self.getkeysize = dlg.GetValue() #获取文本框中输入的值
            keySize = self.getkeysize
            tmp = makeKeyFiles('file', int(keySize.encode("utf-8")))  #unicode 编码的数字要先转成str，再转成int
            if tmp != 0:
                print('公私钥文件创建成功！密钥大小：%s' % (keySize))
                self.tc3.AppendText('\n公私钥文件创建成功！密钥大小：%s' % (keySize))
                dlg_tip = wx.MessageDialog(self, u"密钥已创建为 %s 位 \n公私钥文件创建成功！" % self.getkeysize, u"公私钥文件状态", wx.OK)
                dlg_tip.ShowModal()
                dlg_tip.Destroy()
            else:
                print('公私钥文件已存在！')
                self.tc3.AppendText('\n公私钥文件已存在！')
                dlg_tip = wx.MessageDialog(self, u"公私钥文件已存在！", u"公私钥文件状态", wx.OK | wx.ICON_EXCLAMATION)
                dlg_tip.ShowModal()
                dlg_tip.Destroy()
        dlg.Destroy()


    def OnAbout(self,event):
        
        self.messagedata = u"\n软件说明：\n本软件开发仅用于个人毕业设计, 请勿用于商业用途！\n开发人员：孙庆贺\n\
                                                        \n\
							使用流程介绍：\n\
							先登录服务器等待客户端登录\n\
							客户端登录之后会自动接收服务器传送的公约文件\n\
							客户端使用公约文件对信息进行加密\n\
							服务器使用私钥进行解密并保存带本地\n\
							\n\
							软件功能介绍：\n\
							可以打开已创建的密钥文件\n\
							可以计算并生成密钥文件\n\
							可以浏览明文文件并将解密的明文保存到文件\n\
							可以浏览密文文件并将加密的密文保存到文件\n\
							可以将明文内容加密输出到密文框并重定向到文件\n\
							可以将密文内容解密输出到密文框并重定向到文件\n\
							重置操作将删除当前文件夹下的exc、pyc、pem文件"
        dlg = wx.MessageDialog(self, self.messagedata, caption='关于此软件', style = wx.OK)
        dlg.ShowModal()
        dlg.Destroy()
        print('成功打开关于对话框！')
        self.tc3.AppendText('\n成功打开关于对话框！')


    def OnHelp(self,e):
        # Create a message dialog box
        self.messagedata = u"\
\n\
软件说明：\n\
本软件开发仅用于个人毕业设计, 请勿用于商业用途！\n\
开发人员：孙庆贺\n\
\n\
使用流程介绍：\n\
先登录服务器等待客户端登录\n\
再登录客户端等待服务器传送其公钥文件\n\
客户端登录之后服务器会自动传送自己的公钥文件\n\
客户端使用公约文件对机密信息进行加密\n\
客户端将密文信息发送到服务器\n\
服务器自动接收客户端发来的密文信息\n\
服务器可以使用自己的私钥进行解密并选择保存到本地\n\
\n\
各控件功能：\n\
作为服务器登录：将本机用作服务器\n\
作为客户端登录：将本机用作客户端\n\
向服务器发送密文：客户端向服务器发送密文\n\
信息框：会显示本软件的基本信息\n\
打开密钥文件：查看公钥和私钥数据\n\
生成密钥文件：根据输入的密钥位数计算并生成公钥和私钥\n\
关于：本软件为个人毕业设计，仅供学习交流\n\
帮助：将显示此帮助内容\n\
退出：退出此软件\n\
重置：重置此软件环境\n\
浏览：显示要加密的明密文文件路径\n\
另存为：将已加密的明密文另存为文件\n\
明文：显示要加密或已解密的明文数据\n\
密文：显示要解密或已加密的密文数据\n\
RSA加密：将明文内容加密的同时输出到密文文本框并重定向到密文文件\t\n\
RSA解密：将密文内容解密的同时输出到明文文本框并重定向到明文文件\t\n\
个人博客：http://blog.csdn.net/kevinhanser"

        
        dlg = wx.MessageDialog(self,self.messagedata , u"帮助信息", wx.OK | wx.ICON_AUTH_NEEDED|wx.ICON_QUESTION)
        #dlg = wx.MessageDialog(self, message, caption)
        dlg.ShowModal() # Shows it
        print('成功打开帮助对话框！')
        self.tc3.AppendText('\n成功打开帮助对话框！')

                
        
    def OnExit(self,e):
        dlg = wx.MessageDialog(self, u"确定退出程序？", u"文本状态", wx.OK | wx.CANCEL | wx.ICON_EXCLAMATION)
        if dlg.ShowModal() == wx.ID_OK: # Shows it
            self.Close(True)  # Close the frame.
        dlg.Destroy() # finally destroy it when finished.
        print('您已退出此程序！')
        self.tc3.AppendText('\n您已退出此程序！')
        
                
        
    def OnReset(self,e):
        #弹框
        self.messagedata = u"此操作将会清空缓冲区并删除当前目录下所有数据文件！"
        dlg = wx.MessageDialog(self, self.messagedata, caption='重置此软件', style = wx.OK|wx.CANCEL|wx.ICON_EXCLAMATION)
        if dlg.ShowModal() == wx.ID_OK:
            self.messagedata = u"将删除当前目录内所有*.exc、*.pem及*.pyc文件！\n确认操作？"
            dlg = wx.MessageDialog(self, self.messagedata, caption='确认操作？', style = wx.OK|wx.CANCEL|wx.ICON_EXCLAMATION)
            #dlg.SetOKCancelLabels('重置','取消')
            if dlg.ShowModal() == wx.ID_OK:
                try:
                    #删除当前文件夹下的非*.py和非*.bak文件
                    dir = os.getcwd()
                    #print(dir)
                    topdown=True
                    for root, dirs, files in os.walk(dir, topdown):  
                        for name in files:  
                            pathname = os.path.splitext(os.path.join(root, name))  
                            if (pathname[1] == ".exc" or pathname[1] == ".pem" or pathname[1] == ".pyc"):  
                                os.remove(os.path.join(root, name))  
                                #print(os.path.join(root,name))
                except PermissionError:
                    print('文件已被占用，正在退出程序')
                    
                    dlg1 = wx.MessageDialog(self, '文件已被占用，正在退出程序...', caption='正在退出程序', style = wx.OK|wx.ICON_ERROR)
                    dlg1.ShowModal()
                    dlg1.Destory()

                    
                #清除文本框缓冲区
                filepath1.Clear()
                filepath2.Clear()
                self.tc1.Clear()
                self.tc2.Clear()
                self.tc3.Clear()
                #弹框
                print('已清空缓冲区并已删除所有数据文件！')
                self.tc3.AppendText('\n已清空缓冲区并已删除所有数据文件！')
                self.messagedata = u"已清空缓冲区并已删除所有数据文件！"
                dlg2 = wx.MessageDialog(self, self.messagedata, caption='重置此软件', style = wx.OK|wx.ICON_EXCLAMATION)
                dlg2.ShowModal()
               







    def rec(self,sock):
        while 1:
            try:
                t=sock.recv(1024).decode('utf8')  #函数的核心语句就一条接收方法
            except ConnectionResetError:

                dlg = wx.MessageDialog(self, '远程主机已关闭连接，正在退出程序...', caption='远程主机已关闭', style = wx.OK|wx.ICON_ERROR)
                print('远程主机已关闭连接，正在退出程序...')
                self.tc3.AppendText('\n远程主机已关闭连接，正在退出程序...')
                if dlg.ShowModal() == wx.ID_OK:
                    self.Close(True)
                dlg.Destory()


                
            print('\n已经接收到密文信息，可以进行解密...')
            #print(t)
            self.tc3.AppendText('\n已经接收到密文信息，可以进行解密...')
            self.tc2.AppendText(t)


    def send(self,sock):
        tmp = 1
        while 1:
            
            fo = open(recvpubkeyfilename)
            t = fo.read()
            fo.close()
            if tmp == 1:
                sock.send(t.encode('utf8'))
                tmp += 1


    def recs(self,s):
        tmp = 1
        while tmp != 0:
            tmp -= 1
            try:
                t=s.recv(1024).decode("utf8")  #客户端也同理
            except ConnectionResetError:
                print('远程主机强迫关闭了一个现有的连接')
                self.tc3.AppendText('远程主机强迫关闭了一个现有的连接')

                dlg2 = wx.MessageDialog(self, u"远程主机强迫关闭了一个现有的连接,正在退出...", u"正在退出", wx.OK | wx.ICON_ERROR)
                dlg2.ShowModal()
                self.Close(True)
            print('\n已经接收到公钥信息...')
            #print(t)
            self.tc3.AppendText('\n已经接收到公钥信息...')
            #self.tc3.AppendText('\n%s' % t)

            
            dlg2 = wx.MessageDialog(self, u"已经接收到服务器传来的公钥信息\n请将公钥信息保存为文件...", u"公钥文件", wx.OK | wx.CANCEL| wx.ICON_INFORMATION)
            print('已经接收到服务器传来的公钥信息\n请将公钥信息保存为文件...')
            self.tc3.AppendText('\n已经接收到服务器传来的公钥信息\n请将公钥信息保存为文件...')
            if dlg2.ShowModal() == wx.ID_OK:
                    dlg = wx.FileDialog(self,
                                message=u"将公钥信息保存为文件：",
                                defaultDir=fileDir,
                                defaultFile="file_pubkey.pem",
                                wildcard=wildcard2,
                                style=wx.FD_SAVE|wx.FD_OVERWRITE_PROMPT
                                )
                    if dlg.ShowModal() == wx.ID_OK:
                        
                        file=open(dlg.GetPath(),'w')
                        file.write(t)
                        file.close()
                    dlg.Destroy()
            dlg2.Destroy()

            dlg_3 = wx.MessageDialog(self, u"已成功接收公钥信息，可以进行信息加密...", u"接收成功", wx.OK | wx.ICON_EXCLAMATION)
            print('已成功接收公钥信息，可以进行信息加密...')
            self.tc3.AppendText('\n已成功接收公钥信息，可以进行信息加密...')
            dlg_3.ShowModal()




            
    def sends(self,s):
        tmp = 1
        while 1:
            try:
                ciphermessage = self.tc2.GetValue()
            except RuntimeError:
                pass
                
            if tmp == 1:
                s.send(ciphermessage.encode('utf8'))
                tmp += 1





















    def OnSendClick(self, event):
        #self.sendButton.SetLabel("Clicked")

        
        
        #trd=threading.Thread(target=self.recs,args=(s,))  
        #trd.start()

        dlg_tip = wx.MessageDialog(self, u"是否已作为客户端连接到服务器？", u"请请确认已作为客户端连接到服务器", wx.YES_NO |wx.ICON_EXCLAMATION)
        if dlg_tip.ShowModal() == wx.ID_YES:
            try:
                if auth == 121:
                    trd=threading.Thread(target=self.sends,args=(s,))  
                    trd.start()
                    print('已将密文发送给服务器')
                    self.tc3.AppendText('\n已将密文发送给服务器')

                #s.close()
            except NameError:
                dlg_3 = wx.MessageDialog(self, u"当前客户端未与服务器成功连接，正在退出程序...", u"接收成功", wx.OK | wx.ICON_ERROR)
                if dlg_3.ShowModal() == wx.ID_OK:
                    self.Close(True)


    def OnSeverClick(self, event):
        trd=threading.Thread(target=self.server1,args=(event,))
        trd.setDaemon(True) 
        trd.start()



    def server1(self, event):

        global sock
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        try:
            s.bind(("0.0.0.0",9999))
            s.listen(5)
            
            dlg_tip = wx.MessageDialog(self, u"正在等待客户端登录......", u"等待客户端登录......", wx.OK |wx.ICON_EXCLAMATION)
            if dlg_tip.ShowModal() == wx.ID_OK:
                dlg_1 = wx.MessageDialog(self, u"客户端是否已经登录？", u"客户端是否已经登录", wx.OK | wx.CANCEL | wx.ICON_EXCLAMATION)
                
               
                if dlg_1.ShowModal() == wx.ID_OK:

                    print('正在本机监听客户端连接, 请登录客户端...')
                    self.tc3.AppendText('\n正在本机监听客户端连接, 请登录客户端...')
                    
                    
                    sock,addr=s.accept()
                    

                    print('客户端已登录！')
                    self.tc3.AppendText('\n客户端已登录....')
                    
                    if os.path.exists('file_pubkey.pem') == True:

                        dlg_5 = wx.MessageDialog(self, u"公钥文件已存在，即将把公钥文件发送给客户端..." , u"公私钥文件状态", wx.OK)
                        dlg_5.ShowModal()
                        print('公钥文件已存在，即将把公钥文件发送给客户端...')
                        self.tc3.AppendText('\n公钥文件已存在，即将把公钥文件发送给客户端...')

                        
                        dlg = wx.FileDialog(
                            self,defaultFile="file_pubkey.pem",
                            message=u"选择要传输的公钥文件",
                            defaultDir=fileDir,
                            wildcard=wildcard2,
                            style=wx.FD_OPEN | wx.FD_MULTIPLE)
                        global recvpubkeyfilename
                        if dlg.ShowModal() == wx.ID_OK:
                            recvpubkeyfilename = dlg.GetPath()
                    else:

                        #print('公钥文件不存在！ 正在重新生成密钥文件...')
                        #self.tc3.AppendText('\n公钥文件不存在！ 正在重新生成密钥文件....')
                        
                        dlg_3 = wx.MessageDialog(self, u"公钥文件不存在！ 正在重新生成密钥文件！", u"正在重新生成公钥文件...", wx.OK | wx.CANCEL | wx.ICON_EXCLAMATION)
                        if dlg_3.ShowModal() == wx.ID_OK:
                            
                                makeKeyFiles('file', 1024)  #unicode 编码的数字要先转成str，再转成int
                                
                                print('公私钥文件创建成功！密钥大小：1024')
                                self.tc3.AppendText('公私钥文件创建成功！密钥大小：1024')
                                dlg_5 = wx.MessageDialog(self, u"密钥已创建为 1024 位 \n公私钥文件创建成功！\n正在将公钥文件传送到客户端，请稍候...", u"公私钥文件状态", wx.OK)
                                dlg_5.ShowModal()
                                    
                        #if os.path.exists('file_pubkey.pem') == True:
                            #dlg = wx.FileDialog(
                                #self,defaultFile="file_pubkey.pem",
                                #message=u"选择要传输的公钥文件",
                                #defaultDir=fileDir,
                                #wildcard=wildcard2,
                                #style=wx.FD_OPEN | wx.FD_MULTIPLE)
                            #global recvpubkeyfilename
                            #if dlg.ShowModal() == wx.ID_OK:
                        recvpubkeyfilename = 'file_pubkey.pem'
                            
                    
                    trd=threading.Thread(target=self.rec,args=(sock,))
                    trd.setDaemon(True) 
                    trd.start()
                    
                    trd=threading.Thread(target=self.send,args=(sock,))
                    trd.setDaemon(True) 
                    trd.start()

                    #s.close()
                else:
                    print('\n客户端未登录！')
                    self.tc3.AppendText('\n客户端未登录....')
                dlg_1.Destroy()
            dlg_tip.Destroy()

            
        except OSError:
            print('已经作为服务器监听中...')
            self.tc3.AppendText('\n已经作为服务器监听中...')
        
        
        
        




    def OnClientClick(self, event):


        global s

        dlg = wx.TextEntryDialog(self, u"请输入服务器 IP 地址：",u"服务器 IP 地址", u"172.16.10.145")
        if dlg.ShowModal() == wx.ID_OK:
            serveripaddr = dlg.GetValue() #获取文本框中输入的值

            s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            dlg_1 = wx.MessageDialog(self, u"正在与服务器进行连接，请稍候...", u"正在连接...", wx.OK | wx.ICON_EXCLAMATION)
            print('正在与服务器进行连接，请稍候...')
            self.tc3.AppendText('\n正在与服务器进行连接，请稍候...')
            if dlg_1.ShowModal() == wx.ID_OK:
                try:
                    appli = s.connect((serveripaddr,9999))
                
                    global auth
                    
                    if appli == None:
                        auth = 121   #连接成功 auth 为121

                    dlg_2 = wx.MessageDialog(self, u"客户端已成功登录！\n正在准备接收服务器传送的公钥文件...", u"客户端成功登录", wx.OK | wx.CANCEL | wx.ICON_EXCLAMATION)
                    dlg_2.ShowModal()
                    

                    print('客户端已成功登录！\n正在准备接收服务器传送的公钥文件...')
                    self.tc3.AppendText('\n客户端已成功登录！\n正在准备接收服务器传送的公钥文件...')
                    
                    trd=threading.Thread(target=self.recs,args=(s,))
                    trd.setDaemon(True) 
                    trd.start()

                    #trd=threading.Thread(target=self.sends,args=(s,))  
                    #trd.start()

                    #s.close()
                except ConnectionRefusedError:
                    dlg_1 = wx.MessageDialog(self, u"无法与服务器进行连接，正在退出...", u"正在退出...", wx.OK | wx.ICON_ERROR)
                    print('无法与服务器进行连接，正在退出...')
                    self.tc3.AppendText('\n无法与服务器进行连接，正在退出....')
                    if dlg_1.ShowModal() == wx.ID_OK:
                        self.Close()
                except TimeoutError:
                    dlg_1 = wx.MessageDialog(self, u"无法与服务器进行连接，正在退出...", u"正在退出...", wx.OK | wx.ICON_ERROR)
                    print('无法与服务器进行连接，正在退出...')
                    self.tc3.AppendText('\n无法与服务器进行连接，正在退出....')
                    if dlg_1.ShowModal() == wx.ID_OK:
                        self.Close()
        dlg.Destroy()










        
class MyApp(wx.App):
    def __init__(self):
        # 重构__init__方法，将错误信息重定位到文件中;
        # 默认redirect=True，输出到StdOut或StdError;
        # 为防止程序因错误一闪而过无法捕捉信息，可在
        # 控制台中使用python -i example.py来运行程序。
        wx.App.__init__(self, redirect=False, filename=r"./IO.log")

    def OnInit(self):
        frame = MultiTextFrame()
        frame.Show(True)
        return True

    '''
    # python 2.7
    def openpubfile(self,event):
        #self.pubfilename = 'file_pubkey.pem'
        #if os.path.exists(self.pubfilename) == True:
        #    fo = open(self.pubfilename)
        #    self.pubkeyfiledata = fo.read()
        #    fo.close()
        #dlg = wx.RichMessageDialog(self, self.pubkeyfiledata)
        #dlg.ShowCheckBox("Don't show welcome dialog again")
        #dlg.ShowModal()
    
        self.filename = 'file_pubkey.pem'
        if os.path.exists(self.filename) == True:
            fo = open(self.filename)
            pubkeyfiledata = fo.read()
            fo.close()
            info = wx.AboutDialogInfo()
            info.Name = u"公钥文件数据"
            info.Version = "0.0.1 Alpha"
            info.Copyright = u"公钥文件名：file_pubkey.pem  (C) 2018"
            info.Description = wordwrap("PublicKey: %s "% pubkeyfiledata, 500, wx.ClientDC(panel))
            info.WebSite = ("http://http://blog.csdn.net/kevinhanser", u"源码见个人博客主页")
            #info.Developers = [u"开发者：Kevinhanser \n 声明：此软件用于个人毕业设计"]
            #info.License = wordwrap(u"GNU通用公共许可证v2.0", 500, wx.ClientDC(panel))
            # Show the wx.AboutBox
            wx.AboutBox(info)
        else:
            info = wx.AboutDialogInfo()
            info.Name = u"公钥文件不存在"
            info.Copyright = u"GNU通用公共许可证v2.0 (C) 2018 "
            info.Description = wordwrap(u"\n公钥文件: file_pubkey.pem 不存在！\n\t请重新生成公钥文件！\n", 500, wx.ClientDC(panel))
            info.WebSite = ("http://blog.csdn.net/kevinhanser", u"源码见个人博客主页")
            #info.Developers = [u"开发者：Kevinhanser \n 声明：此软件用于个人毕业设计"]
            #info.License = wordwrap("Completely and totally open source!", 500, wx.ClientDC(panel))
            # Show the wx.AboutBox
            wx.AboutBox(info)
    '''

    '''
    # python 2.7
    def openprifile(self,event):
        self.filename = 'file_privkey.pem'
        if os.path.exists(self.filename) == True:
            fo = open(self.filename)
            privkeyfiledata = fo.read()
            fo.close()
            info = wx.AboutDialogInfo()
            info.Name = u"私钥文件数据"
            info.Version = "0.0.1 Alpha"
            info.Copyright = u"私钥文件名：file_privkey.pem  (C) 2018 "
            info.Description = wordwrap("PrivateKey: %s "% privkeyfiledata, 500, wx.ClientDC(panel))
            info.WebSite = ("http://http://blog.csdn.net/kevinhanser", u"源码见个人博客主页")
            #info.Developers = [u"开发者：Kevinhanser \n 声明：此软件用于个人毕业设计"]
            #info.License = wordwrap(u"GNU通用公共许可证v2.0", 500, wx.ClientDC(panel))
            # Show the wx.AboutBox
            wx.AboutBox(info)
        else:
            info = wx.AboutDialogInfo()
            info.Name = u"私钥文件不存在"
            info.Copyright = u"GNU通用公共许可证v2.0 (C) 2018 "
            info.Description = wordwrap(u"\n私钥文件: file_privkey.pem 不存在！\n\t请重新生成私钥文件！\n", 500, wx.ClientDC(panel))
            info.WebSite = ("http://blog.csdn.net/kevinhanser", u"源码见个人博客主页")
            #info.Developers = [u"开发者：Kevinhanser \n 声明：此软件用于个人毕业设计"]
            #info.License = wordwrap(u"GNU通用公共许可证v2.0", 500, wx.ClientDC(panel))
            # Show the wx.AboutBox
            wx.AboutBox(info)
    '''
    '''
    #python2.7
    def OnAbout(self,event):
        info = wx.AboutDialogInfo()
        info.Name = u"关于此软件"
        info.Copyright = u"GNU通用公共许可证v2.0   (C) 2018 "
        info.Description = wordwrap(u"\n本软件开发用于个人毕业设计, 请勿用于商业用途！                                    \n\
    软件功能介绍：\n\
	可以打开已创建的密钥文件\n\
	可以计算并生成密钥文件\n\
	可以浏览明文文件并将解密的明文保存到文件\n\
	可以浏览密文文件并将加密的密文保存到文件\n\
	可以将明文内容加密输出到密文框并重定向到文件\n\
	可以将密文内容解密输出到密文框并重定向到文件\n", 600, wx.ClientDC(panel))
        info.WebSite = ("http://blog.csdn.net/kevinhanser", u"源码见个人博客主页")
        info.Developers = [u"开发者：Kevinhanser \n\n 声明：此软件用于个人毕业设计"]
        info.License = wordwrap(u"GNU通用公共许可证v2.0   (C) 2018 ", 600, wx.ClientDC(panel))
        #Show the wx.AboutBox
        wx.AboutBox(info)
    '''

    '''
    # Create a message dialog box
    dlg = wx.MessageDialog(self, " A sample editor \n in wxPython", "About Sample Editor", wx.OK | wx.ICON_INFORMATION)
    dlg.ShowModal() # Shows it
    dlg.Destroy() # finally destroy it when finished.
    '''
def main():
    app = MyApp()
    app.MainLoop()


if __name__ == "__main__":
    main()


