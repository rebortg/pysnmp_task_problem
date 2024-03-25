
from pysnmp.hlapi import *
from pysnmp.proto.rfc1905 import EndOfMibView

MAP_AUTH_PROTOCOLS = {
    "MD5": usmHMACMD5AuthProtocol,
    "SHA": usmHMACSHAAuthProtocol,
    "SHA224": usmHMAC128SHA224AuthProtocol,
    "SHA256": usmHMAC192SHA256AuthProtocol,
    "SHA384": usmHMAC256SHA384AuthProtocol,
    "SHA512": usmHMAC384SHA512AuthProtocol,
}

MAP_PRIV_PROTOCOLS = {
    "DES": usmDESPrivProtocol,
    "3DES": usm3DESEDEPrivProtocol,
    "AES": usmAesCfb128Protocol,
    "AES192": usmAesCfb192Protocol,
    "AES256": usmAesCfb256Protocol,
}

MIB_SOURCE = ''

class SNMPClient:
    def __init__(self, host, port=161, version=3, community=None, security_username=None, auth_protocol=None, auth_password=None, priv_protocol=None, priv_password=None):
        self.version = version
        self.host = host
        self.port = port
        self.community = community
        self.security_username = security_username
        self.auth_protocol = MAP_AUTH_PROTOCOLS.get(auth_protocol, usmNoAuthProtocol)
        self.auth_password = auth_password
        self.priv_protocol = MAP_PRIV_PROTOCOLS.get(priv_protocol, usmNoPrivProtocol)
        self.priv_password = priv_password
        self.security_parameters = self.build_security_parameters()

    def build_security_parameters(self):
        if self.version in [1, 2]:
            return CommunityData(self.community)
        elif self.version == 3:
            if self.auth_protocol and self.auth_password and self.priv_protocol and self.priv_password:
                return UsmUserData(self.security_username, authKey=self.auth_password, privKey=self.priv_password, authProtocol=self.auth_protocol, privProtocol=self.priv_protocol)
            elif self.auth_protocol and self.auth_password:
                return UsmUserData(self.security_username, authKey=self.auth_password, authProtocol=self.auth_protocol)
            else:
                return UsmUserData(self.security_username)

    def build_objecttype(self, oid, add_mib=True):
        if not isinstance(oid, ObjectIdentity):
            raise ValueError('Invalid OID')
        if add_mib:
            return ObjectType(ObjectIdentity(oid).addMibSource(MIB_SOURCE))
        return ObjectType(ObjectIdentity(oid))

    def bulkwalk(self, oid):
        engine = SnmpEngine()
        iterator = bulkWalkCmd(
                engine,
                self.security_parameters,
                UdpTransportTarget((self.host, self.port)),
                ContextData(),
                0, 50,
                self.build_objecttype(oid, add_mib=False),
                lexicographicMode=False,
        )
        data = []
        while True:
            try:
                errorIndication, errorStatus, errorIndex, varBinds = next(iterator)        
                if errorIndication:
                    print(errorIndication)
                elif errorStatus:
                    print('%s at %s' % (errorStatus.prettyPrint(),
                                errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
                else:
                    if isinstance(varBinds[0][1], EndOfMibView):
                        break
                    #print(varBinds[0].prettyPrint())
                    data.append(varBinds)
            except StopIteration:
                break

        engine.transportDispatcher.closeDispatcher()

        return data

    

host1 = SNMPClient('demo.pysnmp.com', version=2, community='public')
host1.bulkwalk(ObjectIdentity('1.3.6.1.2.1.2.2'))


host2 = SNMPClient('demo.pysnmp.com', version=2, community='public')
host2.bulkwalk(ObjectIdentity('1.3.6.1.2.1.2.2'))

