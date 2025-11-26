'''
	icmp.py
	
	Funciones necesarias para implementar el nivel ICMP
	Autor: Javier Ramos <javier.ramos@uam.es>
	2022 EPS-UAM
'''
from ip import *
from threading import Lock
import struct

import binascii

ICMP_PROTO = 1

ICMP_ECHO_REQUEST_TYPE = 8
ICMP_ECHO_REPLY_TYPE = 0
CODE = 0
ID = 10
SEQ_NUM = 0

timeLock = Lock()
icmp_send_times = {}

def process_ICMP_message(us,header,data,srcIp):
	'''
		Nombre: process_ICMP_message
		Descripción: Esta función procesa un mensaje ICMP. Esta función se ejecutará por cada datagrama IP que contenga
		un 1 en el campo protocolo de IP
		Esta función debe realizar, al menos, las siguientes tareas:
			-Calcular el checksum de ICMP y comprobar si es correcto:
			-Extraer campos tipo y código de la cabecera ICMP
			-Loggear (con logging.debug) el valor de tipo y código
			-Si el tipo es ICMP_ECHO_REQUEST_TYPE:
				-Generar un mensaje de tipo ICMP_ECHO_REPLY como respuesta. Este mensaje debe contener
				los datos recibidos en el ECHO_REQUEST. Es decir, "rebotamos" los datos que nos llegan.
				-Enviar el mensaje usando la función sendICMPMessage
			-Si el tipo es ICMP_ECHO_REPLY_TYPE:
				-Extraer del diccionario icmp_send_times el valor de tiempo de envío usando como clave los campos srcIP e icmp_id e icmp_seqnum
				contenidos en el mensaje ICMP. Restar el tiempo de envio extraído con el tiempo de recepción (contenido en la estructura pcap_pkthdr)
				-Se debe proteger el acceso al diccionario de tiempos usando la variable timeLock
				-Mostrar por pantalla la resta. Este valor será una estimación del RTT
			-Si es otro tipo:
				-No hacer nada

		Argumentos:
			-us: son los datos de usuarios pasados por pcap_loop (en nuestro caso este valor será siempre None)
			-header: estructura pcap_pkthdr que contiene los campos len, caplen y ts.
			-data: array de bytes con el conenido del mensaje ICMP
			-srcIP: dirección IP que ha enviado el datagrama actual.
		Retorno: Ninguno
		  
	'''
	global ICMP_ECHO_REPLY_TYPE, ICMP_ECHO_REQUEST_TYPE, CODE, timeLock, icmp_send_times
	
	#Comprobamos checksum
	if (chksum(data) != 0):
		return
	
	#Extraemos campos
	icmpType = data[0]
	code = data[1]
	icmpId = int.from_bytes(data[4:6], 'big')
	seqNum = int.from_bytes(data[6:8], 'big')
	payload = data[8:]
	
	#Loggueamos
	logging.debug(f'Type: {icmpType}\tCode: {code}')
	
	#Procesamos paquete
	if (icmpType == ICMP_ECHO_REQUEST_TYPE and code == CODE):
		sendICMPMessage(payload, ICMP_ECHO_REPLY_TYPE, CODE, icmpId, seqNum, int.from_bytes(srcIp, 'big'))
	elif (icmpType == ICMP_ECHO_REPLY_TYPE and code == CODE):
		with timeLock:
			if (int.from_bytes(srcIp, 'big') + icmpId + seqNum not in icmp_send_times):
				return
			ti = icmp_send_times[int.from_bytes(srcIp, 'big') + icmpId + seqNum]
		
		rtt = header.ts.tv_sec + (header.ts.tv_usec / 1000000) - ti
		logging.info(f'RTT: {rtt}')
	
	return
	

def sendICMPMessage(data,type,code,icmp_id,icmp_seqnum,dstIP,minSize = 0,padding = b'0'):
	'''
		Nombre: sendICMPMessage
		Descripción: Esta función construye un mensaje ICMP y lo envía.
		Esta función debe realizar, al menos, las siguientes tareas:
			-Si el campo type es ICMP_ECHO_REQUEST_TYPE o ICMP_ECHO_REPLY_TYPE:
				-Construir la cabecera ICMP
				-Añadir los datos al mensaje ICMP
				-Calcular el checksum y añadirlo al mensaje donde corresponda
				-Si type es ICMP_ECHO_REQUEST_TYPE
					-Guardar el tiempo de envío (llamando a time.time()) en el diccionario icmp_send_times
					usando como clave el valor de dstIp+icmp_id+icmp_seqnum
					-Se debe proteger al acceso al diccionario usando la variable timeLock

				-Llamar a sendIPDatagram para enviar el mensaje ICMP
				
			-Si no:
				-Tipo no soportado. Se devuelve False

		Argumentos:
			-data: array de bytes con los datos a incluir como payload en el mensaje ICMP
			-type: valor del campo tipo de ICMP
			-code: valor del campo code de ICMP 
			-icmp_id: entero que contiene el valor del campo ID de ICMP a enviar
			-icmp_seqnum: entero que contiene el valor del campo Seqnum de ICMP a enviar
			-dstIP: entero de 32 bits con la IP destino del mensaje ICMP
		Retorno: True o False en función de si se ha enviado el mensaje correctamente o no
		  
	'''
	global ICMP_ECHO_REQUEST_TYPE, ICMP_ECHO_REPLY_TYPE, timeLock, icmp_send_times, ICMP_PROTO
	
	#Control de errores: Tipo no soportado
	if (type not in [ICMP_ECHO_REPLY_TYPE, ICMP_ECHO_REQUEST_TYPE]):
		return
	
	icmp_message = bytearray()

	#Construimos paquete
	icmp_message[0:1] = (type).to_bytes(1, 'big')
	icmp_message[1:2] = (code).to_bytes(1, 'big')
	icmp_message[2:4] = bytes([0x00, 0x00])
	icmp_message[4:6] = icmp_id.to_bytes(2, 'big')
	icmp_message[6:8] = icmp_seqnum.to_bytes(2, 'big')
	icmp_message[8:] = data
	
	#Añadimos relleno para que el paquete sea del tamaño pedido
	while(len(icmp_message) < minSize):
		icmp_message[len(icmp_message):] = padding[0:minSize - len(icmp_message)]
	
	#Checksum: Numero de bytes pares
	if (len(icmp_message) % 2 != 0):
		icmp_message.append(0)
	
	#Checksum: Calculo
	icmp_message[2:4] = chksum(icmp_message).to_bytes(2, 'little')
	
	#Si es Echo Request
	if (type == ICMP_ECHO_REQUEST_TYPE):
		with timeLock:
			icmp_send_times[dstIP + icmp_id + icmp_seqnum] = time.time()
			
	sendIPDatagram(dstIP, icmp_message, ICMP_PROTO)


def initICMP():
	'''
		Nombre: initICMP
		Descripción: Esta función inicializa el nivel ICMP
		Esta función debe realizar, al menos, las siguientes tareas:
			-Registrar (llamando a registerIPProtocol) la función process_ICMP_message con el valor de protocolo 1

		Argumentos:
			-Ninguno
		Retorno: Ninguno
		  
	'''
	global ICMP_PROTO
	
	registerIPProtocol(process_ICMP_message, ICMP_PROTO)