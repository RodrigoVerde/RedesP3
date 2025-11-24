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
SIOCGIFMTU = 0x8921
SIOCGIFNETMASK = 0x891b
#Diccionario de protocolos. Las claves con los valores numéricos de protocolos de nivel superior a IP
#por ejemplo (1, 6 o 17) y los valores son los nombres de las funciones de callback a ejecutar.
protocols={}
#Tamaño mínimo de la cabecera IP
IP_MIN_HLEN = 20
#Tamaño máximo de la cabecera IP
IP_MAX_HLEN = 60

ETHERTYPE = 0x0800
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
    # Extraer campos de la cabecera
    
    # Comprobar si hay datos suficientes para la cabecera mínima
    if len(data) < 20:
        logging.warning("Datagrama IP recibido demasiado corto.")
        return

    byte_0 = data[0]
    version = byte_0 >> 4       
    ihl_raw = byte_0 & 0x0F     
    ihl_en_bytes = ihl_raw * 4 

    # Comprobar si los datos recibidos coinciden con la longitud de cabecera
    if len(data) < ihl_en_bytes:
        logging.warning("Datos del paquete más cortos que la IHL especificada.")
        return

    tipo_servicio = data[1] 
    longitud_total = (data[2] << 8) + data[3]
    identificacion = (data[4] << 8) + data[5]

    byte_6 = data[6] 
    byte_7 = data[7] 
    flags_raw = byte_6 >> 5   
    flag_df = (flags_raw & 0b010) > 0  
    flag_mf = (flags_raw & 0b001) > 0  
    offset = ((byte_6 & 0x1F) << 8) + byte_7 
    
    timeToLive = data[8]
    protocolo = data[9] 
    headerChecksum = data[10:12] 

    ip_origen_bytes = data[12:16]
    ipOrigen = socket.inet_ntoa(ip_origen_bytes)
    ip_destino_bytes = data[16:20]
    ipDestino = socket.inet_ntoa(ip_destino_bytes)

    # Comprobar Checksum
    
    header_para_calcular = bytearray(data[:ihl_en_bytes])
    header_para_calcular[10] = 0
    header_para_calcular[11] = 0

    chksumCalculado_int = chksum(header_para_calcular)
    
    try:
        chksumCalculado_bytes = struct.pack('H', chksumCalculado_int)
    except struct.error:
        logging.warning("Error al empaquetar checksum calculado.")
        return

    if (chksumCalculado_bytes != headerChecksum):
        logging.debug("Checksum IP incorrecto. Descartando paquete.")
        return 
    
    #  Loggear campos solicitados
    logging.debug("--- CAMPOS DE LA CABECERA IP ---")
    logging.debug(f"Longitud Cabecera: {ihl_en_bytes} bytes")
    logging.debug(f"IPID:              {identificacion}")
    logging.debug(f"TTL:               {timeToLive}")
    logging.debug(f"Flag DF:           {flag_df}")
    logging.debug(f"Flag MF:           {flag_mf}")
    logging.debug(f"Offset:            {offset*8}") 
    logging.debug(f"Protocolo:         {protocolo}")
    logging.debug(f"IP Origen:         {ipOrigen}")
    logging.debug(f"IP Destino:        {ipDestino}")

    #  Comprobar Fragmentación 
    if (offset != 0 or flag_mf):
        logging.debug("Paquete IP fragmentado. Descartando (no se reensambla).")
        return
    
    #  Pasar al Nivel Superior 
    
    if (protocolo not in protocols):
        logging.debug(f"Protocolo IP {protocolo} desconocido. Descartando.")
        return 
    
    payload = data[ihl_en_bytes:]
    
    logging.debug(f"Pasando {len(payload)} bytes de datos al handler del protocolo {protocolo}")
    protocols[protocolo](payload)



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

    protocols[protocol] = callback

def initIP(interface,opts=None):
    global myIP, MTU, netmask, defaultGW,ipOpts, IPID
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

    if (initARP(interface) == -1):
        return False

    myIP = getIP()
    MTU = getMTU()
    netmask = getNetmask()
    defaultGW = getDefaultGW()
    ipOpts = opts

    registerEthCallback(process_IP_datagram, ETHERTYPE)

    IPID = 0x000A

    return True

def sendIPDatagram(dstIP,data,protocol):
    global IPID
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

    
    ip_header = bytearray(20)
    ip_header[0] = 0x40
    ip_header[1] = 0x01
    ip_header[2:4] = struct.pack('!H', 0)
    ip_header[4:6] = struct.pack('!H', IPID)
    ip_header[6:8] = struct.pack('!H', 0)
    ip_header[8] = 64
    ip_header[9] = protocol
    ip_header[10:12] = struct.pack('!H', 0)
    ip_header[12:16] = struct.pack('!I', myIP)
    ip_header[16:20] = struct.pack('!I', dstIP)

    if(ipOpts is not None):
        ip_header[20:] = ipOpts
        while len(ip_header) % 4 != 0:
            ip_header.append(0x00)
    
    header_len = len(ip_header)

    if(header_len > 60):
        return False
    
    ip_header[0] = ip_header[0] + header_len//4

    max_payload = MTU - header_len
    
    if max_payload <= 0:
        print("Error: MTU demasiado pequeño para la cabecera")
        return False
    
    block_size = (max_payload // 8) * 8


    offset = 0 
    total_data_len = len(data)

    while offset < total_data_len:
        
        remaining = total_data_len - offset
        
        if remaining > max_payload:
            current_payload_len = block_size
            more_fragments = True
        else:
            current_payload_len = remaining
            more_fragments = False
            
        # Extraer el trozo de datos
        chunk = data[offset : offset + current_payload_len]
        
        current_header = bytearray(ip_header)
        
        # Configurar Longitud Total 
        total_len = header_len + current_payload_len
        current_header[2:4] = struct.pack('!H', total_len)
        
        # Configurar Flags y Offset
        frag_offset = offset // 8
        
        # Flags: Bit MF 
        flags_offset_value = frag_offset
        if more_fragments:
            flags_offset_value = flags_offset_value | 0x2000 
            
            
        
        current_header[6:8] = struct.pack('!H', flags_offset_value)
        
        # Calcular Checksum
        chk_val = chksum(current_header) 
        current_header[10:12] = struct.pack('H', chk_val)
        
        # Ensamblar paquete final
        packet_to_send = current_header + chunk
        


        # Calcular la direccion destino
        network_source = myIP & netmask
        network_dest = dstIP & netmask


        if network_source == network_dest:
            next_hop_ip = dstIP
        else:
            next_hop_ip = defaultGW

        mac_dest = ARPResolution(next_hop_ip)
        sendEthernetFrame(packet_to_send, total_len, ETHERTYPE, mac_dest )

        offset += current_payload_len

    IPID += 1
    return True

