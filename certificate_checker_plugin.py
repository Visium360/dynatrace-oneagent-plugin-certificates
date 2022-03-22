from ruxit.api.base_plugin import BasePlugin
from ruxit.api.data import PluginProperty, MEAttribute
from ruxit.api.selectors import ListenPortSelector
from  datetime import datetime, timezone, timedelta
import logging
import threading
import time
import ssl
import asn1crypto
import asn1crypto.x509
import re

class CertificateCheckerPluginResult:
    def __init__(self, sni, certificate):
        self.sni = sni
        self.certificate = certificate
        self.discover_event = time.time()      

# Check thread
class SSLPortChecker(threading.Thread):
    def __init__(self, binding, plugin):
        threading.Thread.__init__(self)
        self.binding = binding
        self.plugin = plugin

    def run(self):
        certs = []
        self.plugin.logger.debug("CertificateCheckerPlugin - SSLPortCheckerThread - Checking {b}".format(b=self.binding))
        try:
            # Preparing the connection
            self.plugin.logger.debug("CertificateCheckerPlugin - SSLPortCheckerThread - Connecting {b}".format(b=self.binding))
            with ssl.create_connection(("127.0.0.1", self.binding)) as connection:
                connection.settimeout(3)
                context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                
                # Opening the socket
                self.plugin.logger.debug("CertificateCheckerPlugin - SSLPortCheckerThread - Opening Socket {b}".format(b=self.binding))
                with context.wrap_socket(connection) as sock:
                    
                    self.plugin.logger.debug("CertificateCheckerPlugin - SSLPortCheckerThread - Loading Certitificate from port {b}".format(b=self.binding))
                    # Retrieve the certificate
                    remote_cert=asn1crypto.x509.Certificate.load(sock.getpeercert(True))        
                    certs.append(CertificateCheckerPluginResult(sni="", certificate=remote_cert['tbs_certificate']))
                    serial=remote_cert['tbs_certificate']['serial_number'].native
                    
                    # try additional SNI
                    for sni in self.plugin.additional_sni:
                        self.plugin.logger.debug("CertificateCheckerPlugin - SSLPortCheckerThread - checking {b} SNI {s}".format(b=self.binding, s=sni))
                        connection = ssl.create_connection(self.binding)
                        connection.settimeout(3)
                        context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                        sock = context.wrap_socket(connection, server_hostname=sni)
                        remote_cert = asn1crypto.x509.Certificate.load(sock.getpeercert(True))
                        # Only add certificate if differs from main certificate
                        if (remote_cert['tbs_certificate']['serial_number'].native!=serial):
                            certs.append(CertificateCheckerPluginResult(sni=sni, certificate=remote_cert['tbs_certificate']))        
        
        except Exception:
            self.plugin.logger.debug("CertificateCheckerPlugin - SSLPortCheckerThread - checking {b} - error/timed out".format(b=self.binding))            
        
        self.plugin.logger.debug("CertificateCheckerPlugin - SSLPortCheckerThread - finished checking {b}".format(b=self.binding))            
        self.plugin.sslinfo[self.binding] = certs

# Main Plugin Class
class CertificateCheckerPlugin(BasePlugin):
    checkBindings=[]
    sslinfo={}
    lastCheck=0

    firstRun = True

    LOCAL_TIMEZONE = datetime.now(timezone.utc).astimezone().tzinfo

    # Plugin Entrypoint
    def initialize(self, **kwargs):        
        self.logger.debug("CertificateCheckerPlugin - Initializing")
        self.inclusivePortRange=self.parseRanges(self.config["ports_include"])
        self.exclusivePortRange=self.parseRanges(self.config["ports_exclude"])
        if self.config["additional_sni"]:
            self.additional_sni = re.split('[ ;,]+',self.config["additional_sni"])
        else: 
            self.additional_sni = []
        self.discoverPorts()
        self.checkPorts() 
    
    # Discovers TCP listen ports to check based on Process Groups identified by OneAgent
    def discoverPorts(self):        
        discovered_bindings=[]
        
        # Iteration across all process groups to get port binding
        process_groups_list = self.find_all_process_groups(lambda entry: entry.group_name.startswith(""))     
        self.logger.debug("CertificateCheckerPlugin - {pgl} identified proccess groups".format(pgl=len(process_groups_list)))
         
        for process_group in process_groups_list:
            self.logger.debug("CertificateCheckerPlugin - Checking ports for process {process_group}".format(process_group=process_group))
            
            # Retrieving binding for process group
            port_bindings = self.getPorts(process_group)
            self.logger.debug("CertificateCheckerPlugin - {bindings} binding detected for process group {pg}"
                                          .format(bindings=len(port_bindings), pg=process_group.group_name))
            
            # Check all bindings
            for binding in port_bindings:
                self.logger.debug("CertificateCheckerPlugin - Checking binding {binding} for process group {pg}"
                                          .format(binding=binding, pg=process_group.group_name))
                
                if (self.portInCheckRanges(binding)):
                    # Skipping OneAgent ports itself for sanity
                    if (process_group.group_name != "OneAgent system monitoring"):
                        self.logger.debug("CertificateCheckerPlugin - Port binding {binding} for process group {pg} is matching detection rules"
                                          .format(binding=binding, pg=process_group.group_name))
                        discovered_bindings.append(binding)
        
        self.logger.debug("CertificateCheckerPlugin - {binding} identified binding".format(binding=len(discovered_bindings)))
        
        # Compare identified binding with previously identified binding in order to force the certificate refresh             
        if ((set(self.checkBindings) != set(discovered_bindings)) or self.config['debug']):
            self.logger.debug("CertificateCheckerPlugin - Discovered ports do not match previously"
                              + " discovered ports, forcing recheck")
            self.lastCheck = 0
        else:
            self.logger.debug("CertificateCheckerPlugin - Discovered ports match previously discovered ports.")
        
        self.checkBindings=discovered_bindings   
            
    # Parse port range string
    def parseRanges(self, range_string: str):
        ranges = []
        for range in range_string.split(";"):
            range_re = re.search("(\d+)\s*-\s*(\d+)", range)
            if (range_re):
                ranges.append([ int(range_re.group(1)), int(range_re.group(2))])
            else: 
                range_re = re.search("(\d+)", range)
                if (range_re):
                    ranges.append([ int(range_re.group(1)), int(range_re.group(1))])
        return ranges

    # Check if port within the range
    def portInCheckRanges(self, port: int):
        is_in_range = False
        for in_range in self.inclusivePortRange:
            if (in_range[0] <= port <= in_range[1]):
                is_in_range = True
        for in_range in self.exclusivePortRange:
            if (in_range[0] <= port <= in_range[1]):
                is_in_range = False
        return is_in_range     

    # Trigger check threads
    def checkPorts(self):   
        self.lastCheck = time.time()    
        self.logger.debug("CertificateCheckerPlugin - Start the port checker process in a new Thread")
        for b in self.checkBindings:
            t = SSLPortChecker(b,self)
            t.start()
    
    # List detected ports from the process group       
    def getPorts(self, entity):
        port_set = set()
        if not hasattr(entity, 'processes'):
            return port_set
        for process in entity.processes:
            listening_ports = process.properties.get("ListeningPorts", None)
            if listening_ports is None:
                continue
            if isinstance(listening_ports, list):
                for lport in listening_ports:
                    if (" " in lport):
                        for port in lport.split(' '):
                            port_set.add(int(port))
                    else:
                        port_set.add(int(lport))
            else:
                if (" " in listening_ports):
                    for port in listening_ports.split(' '):
                        port_set.add(int(port))
                else:
                    port_set.add(int(listening_ports))
        return port_set

    def dtEventCertProperties(self, certificate:asn1crypto.x509.TbsCertificate, host_port:str=None):
        properties={}
        for cert_prop in ["Subject","Issuer", "Validity"]:
            for k,v in certificate[cert_prop.lower()].native.items():
                if isinstance(v, datetime):
                    properties["{prop} {attr}".format(prop=cert_prop, attr=k)]=v.astimezone(self.LOCAL_TIMEZONE).isoformat()
                else:
                    properties["{prop} {attr}".format(prop=cert_prop, attr=k)]=v
        if host_port:
            properties["Certificate found at"]=host_port
        return properties        

    def query(self, **kwargs):
        # Initializes DEBUG logging in first run or when debug setting is true
        if self.config['debug'] or self.firstRun:
            self.logger.setLevel(logging.DEBUG)
            self.firstRun = False
        else:
            self.logger.info("Setting log level to WARNING (Debug is %s)", self.config['debug'])
            self.logger.setLevel(logging.WARNING)

        self.logger.debug("CertificateCheckerPlugin - time {t} lastcheck {l}".format(t=time.time(), l=self.lastCheck))
        self.discoverPorts()

        if (time.time() > (self.lastCheck + self.config["check_interval"] * 3600) ):
            self.logger.debug("CertificateCheckerPlugin - check interval due")
            self.checkPorts()

        # publish results
        certcount = 0
        for binding in self.sslinfo:
            for check_result in self.sslinfo[binding]:
                cert = check_result.certificate
                entity=ListenPortSelector(port_number = binding)
                host = "127.0.0.1"
                port = binding
                sni = sni=check_result.sni
                if (sni==""):
                    hps="{h}:{p}".format(h=host, p=port)
                else:
                    hps="{h}:{p}/{sni}".format(h=host, p=port, sni=sni)
                self.logger.info("CertificateCheckerPlugin result {hps} subject CN {sub} notvalidbefore {nvb} novalidafter {nva}".format(hps=hps,
                    sub=cert['subject'].native['common_name'],
                    nvb=cert['validity']['not_before'].native,
                    nva=cert['validity']['not_after'].native))
                certcount=certcount+1   
                
                # Store Certificate as metric
                certificate_metrics_dict = {}
                certificate_metrics_dict["serial_number"] = str(cert['serial_number'].native)
                certificate_metrics_dict["subject"] = cert['subject'].native['common_name']
                certificate_metrics_dict["issuer"] = cert["issuer"].native["common_name"]
                certificate_metrics_dict["not_before"] = cert['validity']['not_before'].native.isoformat()
                certificate_metrics_dict["not_after"] = cert['validity']['not_after'].native.isoformat()
                certificate_metrics_dict["valid_days"] = str((cert['validity']['not_after'].native - datetime.now(timezone.utc)).days)
                self.logger.debug("CertificateCheckerPlugin: valid_days: {valid_days}".format(valid_days=certificate_metrics_dict["valid_days"]))
                
                self.results_builder.absolute(
                    key = "certificate", 
                    value = 1.0, 
                    dimensions = certificate_metrics_dict,
                    entity_selector = entity)     
                
                dict_days = {}
                dict_days["serial_number"] = str(cert['serial_number'].native)
                dict_days["subject"] = cert['subject'].native['common_name']
                self.results_builder.absolute(
                    key = "certificate.valid_days", 
                    value = int(certificate_metrics_dict["valid_days"]), 
                    dimensions = dict_days,
                    entity_selector = entity)          
                
                # Generate an alert when certificate is about to expire
                if (cert['validity']['not_after'].native < datetime.now(timezone.utc) + timedelta(days=self.config['days_event_error'])):
                    # sending error event
                    self.results_builder.report_error_event(
                        description="Certificate expiring in less than {expiring} days".format(expiring=self.config['days_event_info']), 
                        title="Certificate due to expire", 
                        entity_selector=entity,
                        properties=self.dtEventCertProperties(cert, hps))
                elif (cert['validity']['not_after'].native < datetime.now(timezone.utc) + timedelta(days=self.config['days_event_info'])):
                    # sending info event
                    self.results_builder.report_custom_info_event(
                        description="Certificate expiring in less than {expiring} days".format(expiring=self.config['days_event_info']), 
                        title="Certificate expiration warning", 
                        entity_selector=entity,
                        properties=self.dtEventCertProperties(cert, hps))

                
                if (self.config["publish_metadata"]==True):
                    # Send certificate metadata to process 
                    self.logger.info("CertificateCheckerPlugin metadata sent for {hps} on subject CN: {sub}".format(
                        hps=hps,
                        sub=cert['subject'].native['common_name']))
                    self.results_builder.add_property(
                        PluginProperty(
                            me_attribute=MEAttribute.CUSTOM_PG_METADATA,
                            entity_selector=entity,
                            key="Certificate [{hps}, {cn}]".format(hps=hps, cn=cert["subject"].native["common_name"]),
                            value="Valid from:{nvb} to {nva} issued by {issuer}".format(
                            nvb=cert['validity']['not_before'].native.isoformat(),
                            nva=cert['validity']['not_after'].native.isoformat(),
                            issuer=cert["issuer"].native["common_name"])))