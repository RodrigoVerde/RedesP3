'''
	ip.py
	
	Funciones necesarias para implementar el nivel IP
	Autor: Javier Ramos <javier.ramos@uam.es>
	2022 EPS-UAM
'''
from ethernet import *
from arp import *
from fcntl import ioctl
import subprocess
import math
import binascii

SIOCGIFMTU = 0x8921
SIOCGIFNETMASK = 0x891b

#Diccionario de protocolos. Las claves con los valores numéricos de protocolos de nivel superior a IP
#por ejemplo (1, 6 o 17) y los valores son los nombres de las funciones de callback a ejecutar.
protocols={}

#Tamaño mínimo de la cabecera IP
IP_MIN_HLEN = 20
#Tamaño máximo de la cabecera IP
IP_MAX_HLEN = 60

#Constantes
VERSION = 0x04
TYPE_OF_SERVICE = 0x1
NUM_PAREJA = 10
TIME_TO_LIVE = 65

myIP = None
MTU = None
netmask = None
defaultGW = None

ETHERTYPE = int.from_bytes(bytes([0x08,0x00]), 'big')

def chksum(msg):
	'''
		Nombre: chksum
		Descripción: Esta función calcula el checksum IP sobre unos datos de entrada dados (msg)
		Argumentos:
			-msg: array de bytes con el contenido sobre el que se calculará el checksum
		Retorno: Entero de 16 bits con el resultado del checksum en ORDEN DE RED
	'''
	s = 0
	y = 0xa29f
	for i in range(0, len(msg), 2):
		if (i+1) < len(msg):
			a = msg[i] 
			b = msg[i+1]
			s = s + (a+(b << 8))
		elif (i+1)==len(msg):
			s += msg[i]
		else:
			raise 'Error calculando el checksum'
	y = y & 0x00ff
	s = s + (s >> 16)
	s = ~s & 0xffff

	return s

def getMTU(interface):
	'''
		Nombre: getMTU
		Descripción: Esta función obteiene la MTU para un interfaz dada
		Argumentos:
			-interface: cadena con el nombre la interfaz sobre la que consultar la MTU
		Retorno: Entero con el valor de la MTU para la interfaz especificada
	'''
	s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
	ifr = struct.pack('16sH', interface.encode("utf-8"), 0)
	mtu = struct.unpack('16sH', ioctl(s,SIOCGIFMTU, ifr))[1]
   
	s.close()
   
	return mtu
   
def getNetmask(interface):
	'''
		Nombre: getNetmask
		Descripción: Esta función obteiene la máscara de red asignada a una interfaz 
		Argumentos:
			-interface: cadena con el nombre la interfaz sobre la que consultar la máscara
		Retorno: Entero de 32 bits con el valor de la máscara de red
	'''
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	ip = fcntl.ioctl(
		s.fileno(),
	   SIOCGIFNETMASK,
		struct.pack('256s', (interface[:15].encode('utf-8')))
	)[20:24]
	s.close()
	return struct.unpack('!I',ip)[0]


def getDefaultGW(interface):
	'''
		Nombre: getDefaultGW
		Descripción: Esta función obteiene el gateway por defecto para una interfaz dada
		Argumentos:
			-interface: cadena con el nombre la interfaz sobre la que consultar el gateway
		Retorno: Entero de 32 bits con la IP del gateway
	'''
	p = subprocess.Popen(['ip r | grep default | awk \'{print $3}\''], stdout=subprocess.PIPE, shell=True)
	dfw = p.stdout.read().decode('utf-8')
	print(dfw)
	return struct.unpack('!I',socket.inet_aton(dfw))[0]
	

def process_IP_datagram(us,header,data,srcMac):
	'''
		Nombre: process_IP_datagram
		Descripción: Esta función procesa datagramas IP recibidos.
			Se ejecuta una vez por cada trama Ethernet recibida con Ethertype 0x0800
			Esta función debe realizar, al menos, las siguientes tareas:
				-Extraer los campos de la cabecera IP (includa la longitud de la cabecera)
				-Calcular el checksum y comprobar que es correcto					
				-Analizar los bits de de MF y el offset. Si el offset tiene un valor != 0 dejar de procesar el datagrama (no vamos a reensamblar)
				-Loggear (usando logging.debug) el valor de los siguientes campos:
					-Longitud de la cabecera IP
					-IPID
					-TTL
					-Valor de las banderas DF y MF
					-Valor de offset
					-IP origen y destino
					-Protocolo
				-Comprobar si tenemos registrada una función de callback de nivel superior consultando el diccionario protocols y usando como
				clave el valor del campo protocolo del datagrama IP.
					-En caso de que haya una función de nivel superior registrada, debe llamarse a dicha funciñón 
					pasando los datos (payload) contenidos en el datagrama IP.
		
		Argumentos:
			-us: Datos de usuario pasados desde la llamada de pcap_loop. En nuestro caso será None
			-header: cabecera pcap_pktheader
			-data: array de bytes con el contenido del datagrama IP
			-srcMac: MAC origen de la trama Ethernet que se ha recibido
		Retorno: Ninguno
	'''
	global VERSION, IP_MIN_HLEN, IP_MAX_HLEN, protocols
	
	#Extraemos la informacion de la cabecera
	version = (data[0] & 0xf0) >> 4
	header_len = (data[0] & 0x0f) 
	type_of_service = data[1]
	total_len = data[2:4]
	identi = data[4:6]
	df = (data[6] & 0x4) >> 2
	mf = (data[6] & 0x2) >> 1
	offset = (int.from_bytes(data[6:8], 'big') & 0x1fff)
	time_to_live = data[8]
	protocol = data[9]
	checksum = data[10:12]
	source_IP = data[12:16]
	dest_IP = data[16:20]
	
	#Control de errores: Verison
	if (version != VERSION):
		return
	
	#Control de errores: Header length correcto
	if (header_len*4 < IP_MIN_HLEN or header_len*4 > IP_MAX_HLEN):
		return
	
	#Control de errores: checksum
	if (chksum(data[0:header_len*4]) != 0):
		return
		
	#Control de errores: Fragmentacion
	if (offset != 0):
		return
		
	#Logging
	a = int.from_bytes(identi, 'big')
	b = str(source_IP[0]) + '.' + str(source_IP[1]) + '.' + str(source_IP[2]) + '.' + str(source_IP[3])
	c = str(dest_IP[0]) + '.' + str(dest_IP[1]) + '.' + str(dest_IP[2]) + '.' + str(dest_IP[3])
	logging.debug(f'Header length: {header_len*4}\nIPID: {a}\nTTL: {time_to_live}\nDF: {df}\nMF: {mf}\nValor de offset: {offset}\nIP origen: {b}\nIP destino: {c}\nProtocolo: {protocol}')
	
	#Control de errores: Protocolo superior
	if (protocol not in protocols):
		return
	
	payload = data[header_len*4:]
	
	protocols[protocol](us, header, payload, source_IP)


def registerIPProtocol(callback,protocol):
	'''
		Nombre: registerIPProtocol
		Descripción: Esta función recibirá el nombre de una función y su valor de protocolo IP asociado y añadirá en la tabla 
			(diccionario) de protocolos de nivel superior dicha asociación. 
			Este mecanismo nos permite saber a qué función de nivel superior debemos llamar al recibir un datagrama IP  con un 
			determinado valor del campo protocolo (por ejemplo TCP o UDP).
			Por ejemplo, podemos registrar una función llamada process_UDP_datagram asociada al valor de protocolo 17 y otra 
			llamada process_ICMP_message asocaida al valor de protocolo 1. 
		Argumentos:
			-callback_fun: función de callback a ejecutar cuando se reciba el protocolo especificado. 
				La función que se pase como argumento debe tener el siguiente prototipo: funcion(us,header,data,srcIp):
				Dónde:
					-us: son los datos de usuarios pasados por pcap_loop (en nuestro caso este valor será siempre None)
					-header: estructura pcap_pkthdr que contiene los campos len, caplen y ts.
					-data: payload del datagrama IP. Es decir, la cabecera IP NUNCA se pasa hacia arriba.
					-srcIP: dirección IP que ha enviado el datagrama actual.
				La función no retornará nada. Si un datagrama se quiere descartar basta con hacer un return sin valor y dejará de procesarse.
			-protocol: valor del campo protocolo de IP para el cuál se quiere registrar una función de callback.
		Retorno: Ninguno 
	'''
	global protocols
	
	protocols[protocol] = callback
	

def initIP(interface,opts=None):
	global myIP, MTU, netmask, defaultGW, ipOpts, ETHERTYPE, IPID
	'''
		Nombre: initIP
		Descripción: Esta función inicializará el nivel IP. Esta función debe realizar, al menos, las siguientes tareas:
			-Llamar a initARP para inicializar el nivel ARP
			-Obtener (llamando a las funciones correspondientes) y almacenar en variables globales los siguientes datos:
				-IP propia
				-MTU
				-Máscara de red (netmask)
				-Gateway por defecto
			-Almacenar el valor de opts en la variable global ipOpts
			-Registrar a nivel Ethernet (llamando a registerCallback) la función process_IP_datagram con el Ethertype 0x0800
			-Inicializar el valor de IPID con el número de pareja
		Argumentos:
			-interface: cadena de texto con el nombre de la interfaz sobre la que inicializar ip
			-opts: array de bytes con las opciones a nivel IP a incluir en los datagramas o None si no hay opciones a añadir
		Retorno: True o False en función de si se ha inicializado el nivel o no
	'''
	if (initARP(interface) < 0):
		return False
	
	myIP = getIP(interface)
	MTU = getMTU(interface)
	netmask = getNetmask(interface)
	defaultGW = getDefaultGW(interface)
	
	#Control de errores: Opciones
	if (opts is not None and len(opts) > IP_MAX_HLEN - 20):
		return
	
	while (opts is not None and len(opts) % 4 != 0):
		opts.append(0)
	
	ipOpts = opts
	
	registerEthCallback(process_IP_datagram, ETHERTYPE)
	
	IPID = NUM_PAREJA
	
	return True
	

def sendIPDatagram(dstIP,data,protocol):
	global IPID, ETHERTYPE, netmask, myIP, ipOpts
	'''
		Nombre: sendIPDatagram
		Descripción: Esta función construye un datagrama IP y lo envía. En caso de que los datos a enviar sean muy grandes la función
		debe generar y enviar el número de fragmentos IP que sean necesarios.
		Esta función debe realizar, al menos, las siguientes tareas:
			-Determinar si se debe fragmentar o no y calcular el número de fragmentos
			-Para cada datagrama o fragmento:
				-Construir la cabecera IP con los valores que corresponda.Incluir opciones en caso de que ipOpts sea distinto de None
				-Calcular el checksum sobre la cabecera y añadirlo a la cabecera
				-Añadir los datos a la cabecera IP
				-En el caso de que sea un fragmento ajustar los valores de los campos MF y offset de manera adecuada
				-Enviar el datagrama o fragmento llamando a sendEthernetFrame. Para determinar la dirección MAC de destino
				al enviar los datagramas se debe hacer unso de la máscara de red:				  
			-Para cada datagrama (no fragmento):
				-Incrementar la variable IPID en 1.
		Argumentos:
			-dstIP: entero de 32 bits con la IP destino del datagrama 
			-data: array de bytes con los datos a incluir como payload en el datagrama
			-protocol: valor numérico del campo IP protocolo que indica el protocolo de nivel superior de los datos
			contenidos en el payload. Por ejemplo 1, 6 o 17.
		Retorno: True o False en función de si se ha enviado el datagrama correctamente o no
		  
	'''
	#Si los datos son luy grandes (más que IP permite) descartamos
	if (ipOpts is not None):
		if (len(data) > (65535 - 20 - len(ipOpts))):
			return
	else:
		if (len(data) > (65535 - 20)):
			return
	
	datagram = bytearray()
	payload_size = None
	
	#Calculo fragmentos
	if (ipOpts is None):
		payload_size = math.floor((MTU - IP_MIN_HLEN) / 8) * 8
	else:
		payload_size = math.floor((MTU - IP_MIN_HLEN - len(ipOpts)) / 8) * 8
	
	num_frag = math.ceil(len(data) / payload_size)
	
	#Calculamos la direccion MAC destino
	if ((netmask & dstIP) == (netmask & myIP)):
		dstMac = ARPResolution(dstIP)
	else:
		dstMac = ARPResolution(defaultGW)
	
	for i in range(num_frag):
		#Creamos los fragmentos
		mf = 0 if (i == num_frag-1) else 1
		datagram_size = len(data) if (num_frag == 1) else payload_size if (i != num_frag-1) else (len(data) - payload_size*i)
		datagram[0:] = createIPHeader(IPID, mf, payload_size*i, protocol, dstIP, datagram_size)
		datagram[len(datagram):] = data[payload_size*i: payload_size*(i+1)]
		
		#Enviamos fragmento
		if (sendEthernetFrame(datagram, len(datagram), ETHERTYPE, dstMac) < 0):
			return False

	IPID += 1 
	
	return True
	

def createIPHeader(ipid, mf, offset, protocol, dstIP, payload_size):
	global ipOpts, VERSION, TYPE_OF_SERVICE, TIME_TO_LIVE, myIP
	header = bytearray()
	
	header[0:1] = (VERSION << 4).to_bytes(1, 'big')
	header[1:2] = (TYPE_OF_SERVICE).to_bytes(1, 'big')
	header[2:4] = bytes([0x00, 0x00])
	header[4:6] = ipid.to_bytes(2, 'big')
	header[6:8] = ((mf << 13) + math.floor(offset/8)).to_bytes(2, 'big')
	header[8:9] = (TIME_TO_LIVE).to_bytes(1, 'big')
	header[9:10] = (protocol).to_bytes(1, 'big')
	header[10:12] = bytes([0x00, 0x00])
	header[12:16] = myIP.to_bytes(4, 'big')
	header[16:20] = dstIP.to_bytes(4, 'big')
	if (ipOpts is not None):
		header[20:] = ipOpts
	
	#Corregimos algunos campos que necesitaban de la cabecera completa
	header[0:1] = (header[0] + math.floor(len(header) / 4)).to_bytes(1, 'big')
	header[2:4] = (len(header) + payload_size).to_bytes(2, 'big')
	header[10:12] = chksum(header).to_bytes(2, 'little')
	
	return header