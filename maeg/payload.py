import logging

l = logging.getLogger("maeg.payload")
l.setLevel('DEBUG')

class Payload(object):
    PTYPES = ['string', 'script']

    def __init__(self, content, ptype):
        self.content = content
        self.ptype = ptype
