#!/usr/bin/env python

"""Test the correlation coefficients of the protocol implementation.
"""

import liuproto.storage, liuproto.link, liuproto.endpoint
from pylab import *

spectrum = zeros(10000)

for i in range(20):
    p = liuproto.endpoint.Physics(10000, 0.3, 0.01, 10, 0)
    storage = liuproto.storage.Session('internal')
    link = liuproto.link.InternalLink(p, storage=storage)
    
    link.run_proto()
    
    run = storage.runs[0]
    
    messages_ab = array([message.message
                    for message in run.messages if message.source == 'Alice'])

    messages_ba = array([message.message
                    for message in run.messages if message.source == 'Bob'])
    
    Z_a = run.endpoints[0].physics.random_values[:-1]
    Z_b = run.endpoints[1].physics.random_values[:-1]
    
    print "% 6.2f % 6.2f % 6.2f % 6.2f" % (mean(messages_ab[1:]*Z_b)/var(Z_b),\
          mean(messages_ba*Z_a)/var(Z_a), \
          mean(messages_ab[:-1]*messages_ba)/var(Z_b), \
          mean(messages_ba*messages_ab[1:])/var(Z_a)), \
        run.results[0].result, run.endpoints[0].physics.reflection_coefficient > 0

    spectrum += (abs(fft(Z_a))**2)

semilogy(spectrum/(i+1))
show()