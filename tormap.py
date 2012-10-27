#!/usr/bin/env python
# encoding: utf-8

'''  
 quick and dirty hack Moritz Bartl moritz@torservers.net
 13.12.2010

 let me know and send me your changes if you improve anything

 requires: 
 - pygeoip, http://code.google.com/p/pygeoip/
 - geoIP city database, eg. http://www.maxmind.com/app/geolitecity

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU Lesser General Public License (LGPL) 
 as published by the Free Software Foundation, either version 3 of the 
 License, or any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU Lesser General Public License for more details.
 
 http://www.gnu.org/licenses/
'''

FAST = 1000000

import base64, shelve, pygeoip, cgi, re
from operator import attrgetter, itemgetter
from string import Template

cachedRelays = dict()
currentRouter = dict()

# parse cached-descriptors to extract uptime and announced bandwidth
with open('cached-descriptors') as f:
    for line in f:				
		line = line.strip()
		if line.startswith('router '):
			[nil,name,ip,orport,socksport,dirport] = line.split()
			currentRouter['name'] = name
			currentRouter['ip'] = ip
			currentRouter['orport'] = orport
			currentRouter['socksport'] = socksport
			currentRouter['dirport'] = dirport
		if line.startswith('platform '):
			currentRouter['version']=line[9:]
		if line.startswith('fingerprint '):
			fingerprint=line[12:]
			currentRouter['fingerprint'] = fingerprint.replace(' ','').lower()	
		if line.startswith('opt fingerprint'):
			fingerprint=line[16:]
			currentRouter['fingerprint'] = fingerprint.replace(' ','').lower()
		if line.startswith('uptime '):
			currentRouter['uptime']=line[7:]
		if line.startswith('bandwidth '):
			currentRouter['bandwidth'] = line[10:]
			try:
				currentRouter['bw-observed'] = int(line.split()[3])			
			except:
				pass
			bandwidth = line[10:]
		if line.startswith('contact '):
			currentRouter['contact'] = cgi.escape(line[8:])
		if line == 'router-signature':
			fingerprint = currentRouter['fingerprint']
			cachedRelays[fingerprint] = currentRouter
			currentRouter = dict()

# parse cached-consensus for flags and correlate to descriptors

badRelays = dict() # Bad in flags, eg. BadExit, BadDirectory
exitFastRelays = dict() # Exit flag, >= FAST
exitRelays = dict() # Exit flag, slower than FAST
stableFastRelays = dict() # Stable flag, but not Exit
stableRelays = dict() # Stable flag, but not Exit
otherRelays = dict() # non Stable, non Exit

count = 0
with open('cached-consensus') as f:
    for line in f:							
		line = line.strip()
		if line.startswith('r '):
			[nil,name,identity,digest,date,time,ip,orport,dirport] = line.split()
			identity = identity.strip()
			fingerprint = base64.decodestring(identity + '=\n').encode('hex')
			# php: unpack('H*',decode_base64($identity))
			currentRouter = dict()
			if fingerprint in cachedRelays:
				currentRouter = cachedRelays[fingerprint]
			# trust consensus more than cached-descriptors, replace info
			currentRouter['fingerprint'] = fingerprint
			currentRouter['name'] = name
			currentRouter['ip'] = ip
			currentRouter['orport'] = orport
			currentRouter['dirport'] = dirport
		if line.startswith('p '):
			currentRouter['policy'] = line[2:]
		if line.startswith('s '):		
			flags = line[2:]
			currentRouter['flags'] = flags			
			if flags.find('Bad')>-1:	
				badRelays[fingerprint] = currentRouter
			elif flags.find('Exit')>-1:
				if currentRouter.has_key('bw-observed') and currentRouter['bw-observed']>FAST:
					exitFastRelays[fingerprint] = currentRouter
				else:
					exitRelays[fingerprint] = currentRouter
			elif flags.find('Stable')>-1:
				if currentRouter.has_key('bw-observed') and currentRouter['bw-observed']>FAST:
					stableFastRelays[fingerprint] = currentRouter
				else:
					stableRelays[fingerprint] = currentRouter
			else:
				otherRelays[fingerprint] = currentRouter

print 'Bad:', len(badRelays)
print 'Exit:', len(exitRelays)
print 'Fast exit:', len(exitFastRelays)
print 'Non-exit stable:', len(stableRelays)
print 'Fast non-exit stable:', len(stableFastRelays)
print 'Other:', len(otherRelays)

inConsensus = len(badRelays)+len(exitRelays)+len(stableRelays)+len(otherRelays)
print '[ in consensus:', inConsensus, ']'
notInConsensus = len(cachedRelays)-len(badRelays)-len(exitRelays)-len(stableRelays)-len(otherRelays)
print '[ cached descriptors not in consensus:', notInConsensus, ']'

# put all relays we want to plot in one list for geoIP
allRelays = dict()
allRelays.update(exitRelays)
allRelays.update(exitFastRelays)
allRelays.update(stableRelays)
allRelays.update(stableFastRelays)
allRelays.update(otherRelays)

# geoIP
geoIPcache = shelve.open('geoip-cache')
geoIPdb = None

for relay in allRelays.values():
	ip = relay['ip']
	if geoIPcache.has_key(ip):
		info = geoIPcache[ip]
	else:
		if geoIPdb is None:
			geoIPdb = pygeoip.GeoIP('GeoLiteCity.dat')
		info = geoIPdb.record_by_addr(ip)
		geoIPcache[ip] = info
	if info is not None:
		relay['location'] = info
		relay['latitude'] = info['latitude']
		relay['longitude'] = info['longitude']
	
geoIPcache.close()

# generate KML

placemarkTemplate = Template ('<Placemark>\n\
	<name>$name</name>\n\
	<description>\n\
	<![CDATA[\n\
	<p>IP: <a href="http://tools.whois.net/whoisbyip/$ip">$ip</a> ORPort: $orport DirPort: $dirport</p>\n\
	<p>Bandwidth: $bandwidth</p>\n\
	<p>Flags: $flags</p>\n\
	<p>Uptime: $uptime</p>\n\
	<p>Contact: $contact</p>\n\
	<p>Policy: $policy</p>\n\
	<p>Fingerprint: <a href="http://torstatus.blutmagie.de/router_detail.php?FP=$fingerprint">$prettyFingerprint</a></p>\n\
	<p>Version: $version</p>\n\
	]]>\n\
	</description>\n\
	<styleUrl>$styleUrl</styleUrl>\n\
	<Point>\n\
		<coordinates>$longitude,$latitude</coordinates>\n\
	</Point>\n\
	</Placemark>\n\
	')
		
kmlBody = ()

def generateFolder(name, styleUrl, relays):
	group = '<Folder>\n<name>%s</name>\n' % name
	for fingerprint,relay in relays.items():
		# for displaying: pretty fingerprint in blocks of four, uppercase		
		relay['prettyFingerprint'] = " ".join(filter(None, re.split('(\w{4})', fingerprint.upper())))
		relay['styleUrl'] = styleUrl
		placemark = placemarkTemplate.safe_substitute(relay)
		group = group + placemark
	group = group + "\n</Folder>"
	return group
	
kmlBody = generateFolder("%s Other" % len(otherRelays), "#other", otherRelays)
kmlBody = kmlBody + generateFolder("%s Stable nodes" % len(stableRelays), "#stable", stableRelays)
kmlBody = kmlBody + generateFolder("%s Fast stable nodes (>= 1MB/s)" % len(stableFastRelays), "#stableFast", stableFastRelays)
kmlBody = kmlBody + generateFolder("%s Exits" % len(exitRelays), "#exit", exitRelays)
kmlBody = kmlBody + generateFolder("%s Fast Exits (>= 1MB/s)" % len(exitFastRelays), "#exitFast", exitFastRelays)

kml = open('tormap.kml', 'w')

kmlHeader = (
	'<?xml version="1.0" encoding="UTF-8"?>\n'
	'<kml xmlns="http://www.opengis.net/kml/2.2" xmlns:gx="http://www.google.com/kml/ext/2.2" xmlns:kml="http://www.opengis.net/kml/2.2" xmlns:atom="http://www.w3.org/2005/Atom">\n'
	'<Document>\n'
	'	<name>Tor relays</name>\n'
	'	<Style id="exit">\n'
	'		<IconStyle>\n'
	'			<Icon>\n'
	'				<href>http://maps.google.com/mapfiles/kml/paddle/grn-blank.png</href>\n'
	'			</Icon>\n'
	'		</IconStyle>\n'
	'	</Style>\n'
	'	<Style id="exitFast">\n'
	'		<IconStyle>\n'
	'			<Icon>\n'
	'				<href>http://maps.google.com/mapfiles/kml/paddle/red-stars.png</href>\n'
	'			</Icon>\n'
	'		</IconStyle>\n'
	'	</Style>\n'
	'	<Style id="stable">\n'
	'		<IconStyle>\n'
	'			<Icon>\n'
	'				<href>http://maps.google.com/mapfiles/kml/paddle/ylw-blank.png</href>\n'
	'			</Icon>\n'
	'		</IconStyle>\n'
	'	</Style>\n'
	'	<Style id="stableFast">\n'
	'		<IconStyle>\n'
	'			<Icon>\n'
	'				<href>http://maps.google.com/mapfiles/kml/paddle/ylw-stars.png</href>\n'
	'			</Icon>\n'
	'		</IconStyle>\n'
	'	</Style>\n'
	'	<Style id="other">\n'
	'		<IconStyle>\n'
	'			<Icon>\n'
	'				<href>http://maps.google.com/mapfiles/kml/paddle/wht-blank.png</href>\n'
	'			</Icon>\n'
	'		</IconStyle>\n'
	'	</Style>\n'
	)
 
kmlFooter = ('</Document>\n'
             '</kml>\n')
 
kml.write(kmlHeader)
kml.write(kmlBody)
kml.write(kmlFooter)
kml.close()
