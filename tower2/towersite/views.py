from django.shortcuts import render
from django.http import JsonResponse
import netifaces, ipaddress, nmap, json
from .models import Node, Image
from influxdb import InfluxDBClient

ip_main = "192.168.1.2"
def getUpdate(self):
  #myIPlist = []
  #myNetworklist = []
  #upHost = []

  #for interface in netifaces.interfaces():
  #  if netifaces.AF_INET in netifaces.ifaddresses(interface):
  #    for address_info in netifaces.ifaddresses(interface)[netifaces.AF_INET]:
  #      address_object = ipaddress.IPv4Address(address_info['addr'])
  #      if not address_object.is_loopback:
  #        myIPlist.append(str(address_info['addr']))
  #        myNetworklist.append(str(ipaddress.ip_network(str(address_info['addr']) + '/' + str(address_info['netmask']), strict=False)))
  
  # Assume only one ip exists
  # 1. Add mid-towers from my db
  # 2. If influxDB access is available, add nodes.
  # 3. Check all nodes status / influxDB, ssh availability

  if len(Node.objects.filter(ip=ip_main)) == 0:
    Node.objects.create(ip=ip_main)

  nodes = []
  upHost = []
  upHostStat = {}
  sshHost = []
  chrHost = []
  kafkaHost = []
  redHost = []
  yellowHost = []
  greenHost = []

  # 1
  try:
    client = InfluxDBClient("localhost", "8086", "Labs")
    result = client.query('SELECT distinct("ip") from "Labs"."autogen"."labs"')

    cnt = 0
    for col in result.raw['series'][0]['columns']:
      if col == 'distinct':
        break
      cnt = cnt + 1

    for data in result.raw['series'][0]['values']:
      if len(Node.objects.filter(ip=data[cnt])) == 0:
        print("Add Mid Con Node")
        print(data[cnt])
        Node.objects.create(ip=data[cnt], pNode=Node.objects.get(ip=ip_main))
      else:
        nodes.append(Node.objects.get(ip=data[cnt]))

  except Exception as e:
    print(e)

  # 2
  # Hierarchial Support....
  """for node in nodes:
    try:
      client = InfluxDBClient(node.ip, "8086", "Labs")
      result = client.query('SELECT distinct("ip") from "Labs"."autogen"."labs"')

      cnt = 0
      for col in result.raw['series'][0]['columns']:
        if col == 'distinct':
          break
        cnt = cnt + 1

      for data in result.raw['series'][0]['values']:
        if len(Node.objects.filter(ip=data[cnt])) == 0:
          print("Add Terminal Node")
          print(data[cnt])
          Node.objects.create(ip=data[cnt], pNode=Node.objects.get(ip=node.ip))

    except Exception as e:
      print(e)"""
  
  #3
  for node in Node.objects.all():
    ip = node.ip
    nm = nmap.PortScanner()
    nm.scan(hosts=ip, arguments='-sP')
    if ip in nm.all_hosts():
      if nm[ip].state() == 'up':
        upHost.append(ip)

    nm.scan(hosts=ip, arguments='-p 22,2181,8888')
    if ip in nm.all_hosts():
      if nm[ip].state() == 'up':
        if nm[ip].has_tcp(22):
          if nm[ip]['tcp'][22]['state'] == 'open':
            sshHost.append(ip)
        if nm[ip].has_tcp(2181):
          if nm[ip]['tcp'][2181]['state'] == 'open':
            kafkaHost.append(ip)
        if nm[ip].has_tcp(8888):
          if nm[ip]['tcp'][8888]['state'] == 'open':
            chrHost.append(ip)
            
  #4
  try:
    client = InfluxDBClient("localhost", "8086", "Labs")
    result = client.query('SELECT "cpu", "ip" FROM "Labs"."autogen"."labs" WHERE time <= now() And time >= now() - 5s order by time desc')

    cpuUsage = {}
    for data in result.raw['series']:
      for i in range(len(data['values'])):
        ip = ""
        cpu = ""
        for column, value in zip(data['columns'], data['values'][i]):
          if column == 'ip':
            ip = value
          if column == 'cpu':
            cpu = value
        if ip not in cpuUsage:
          cpuUsage[ip] = cpu

    for key, val in cpuUsage.items():
      if val <= 0.5:
        greenHost.append(key)
      elif val <= 0.9:
        yellowHost.append(key)
      else:
        redHost.append(key)
  except Exception as e:
    print(e)

  return JsonResponse(json.dumps({"upHost": upHost, "sshHost": sshHost, "chrHost": chrHost, "kafkaHost": kafkaHost, "greenHost": greenHost, "yellowHost": yellowHost, "redHost": redHost}), safe=False)

def getSSH(self):
  results = []
  try:
    client = InfluxDBClient("localhost", "8086", "ssh")
    result = client.query('SELECT * FROM "ssh"."autogen"."ssh" order by time desc limit 5')

    for data in result.raw['series']:
      for i in range(len(data['values'])):
        ip = ""
        success = ""
        time = ""
        for column, value in zip(data['columns'], data['values'][i]):
          if column == 'time':
            time = value
          if column == 'tried':
            ip = value
          elif column == 'success':
            success = value

        results.append({"ip" : ip, "access" : success, "time" : time})

  except Exception as e:
    print(e)

  return JsonResponse(json.dumps(results), safe=False)

def getStatus(self):
  nodes = []
  edges = []
  dic = {}

  cnt = 1
  default_img = Image.objects.all()[0]

  for node in Node.objects.all():
    if node.image == None or node.image.getURL() == "":
      nodes.append({"id" : cnt, "shape" : "circularImage", "image": default_img.getURL(), "label": node.ip, "ip" : node.ip})
    else:
      nodes.append({"id" : cnt, "shape" : "circularImage", "image": node.image.getURL(), "label": node.ip, "ip" : node.ip})

    if node.ip == ip_main:
      nodes[cnt - 1]["label"] = "TOWER"

    dic[node.ip] = cnt

    cnt = cnt + 1

  cnt = 1
  for node in Node.objects.all():
    if node.pNode != None and node.pNode != "":
      edges.append({"id" : cnt, "from" : dic[node.ip], "to" : dic[node.pNode.ip], "arrows" : "to"})
    cnt = cnt + 1

  return JsonResponse(json.dumps({"nodes": nodes, "edges": edges}, sort_keys=True), safe=False)
  
def index(request):
    return render(request, 'towersite/index.html', {})


