import certgen
from OpenSSL import crypto

def gen_root_CA():
    ca_key_pair = certgen.create_key_pair( crypto.TYPE_RSA, 2048 )
    careq = certgen.create_cert_request( ca_key_pair,    
                                                    C= "US",
                                                    ST= "MD",
                                                    L="Frederick",
                                                    O="Hillnetwork",
                                                    OU="Hillnetwork CA",
                                                    CN='Certificate Authority',
                                                    emailAddress="nick@hillnetwork.me" )
    # self signed key 
    cacert = certgen.create_certificate(careq, (careq, ca_key_pair ), 0, (0, 60*60*24*365*5))
    return ca_key_pair, cacert



def dump_keys( key ):
    print( 
    crypto.dump_publickey(crypto.FILETYPE_PEM, key).decode('utf-8') + "\n" + \
    crypto.dump_privatekey(crypto.FILETYPE_PEM, key ).decode('utf-8')
    )


def dump_cert( cert ):
    print( 
    crypto.dump_certificate(crypto.FILETYPE_PEM, cert ).decode('utf-8') 
    )



class CA:

    def __init__( self, key_pair ):
        self.key_pair = key_pair

    def create_certs( self, **name):
        key_pair = certgen.create_key_pair( crypto.TYPE_RSA, 2048 )
        request = certgen.create_cert_request( key_pair, digest="sha256", **name )
        cert = certgen.create_certificate(request, (request, self.key_pair ), 0, (0, 60*60*24*365*5))
        return key_pair, cert



rootCAkeys, rootCAcert = gen_root_CA()
root = CA( rootCAcert )
key_pair, cert = root.create_certs( CN="test" )


