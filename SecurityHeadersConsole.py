#!/bin/python

import urllib2, socket
from urlparse import urlparse

class SecurityHeaderVerifier(object):
	__security_headers = { "content-security-policy":   ["Not Found", ["connect-src", "default-src", "font-src", "frame-src", "img-src", "manifest-src", "media-src", "script-src", "style-src", "worker-src"]],
						   "x-xss-protection":          ["Not Found", ["1","mode=block"]],
						   "strict-transport-security": ["Not Found", ["max-age", "includeSubdomains"]],
						   "x-frame-options":           ["Not Found", ["DENY", "SAMEORIGIN", "ALLOW-FROM"]],
						   "public-keys-pins":          ["Not Found", ["pin-sha256","max-age", "report-uri"]],
						   "x-content-type-options":    ["Not Found", ["nosniff"]] }

	def check_headers(self, info):
		for key in info:
			if key in self.__security_headers:
				for attrib in self.__security_headers[key][1]:
					if attrib in info[key]:
						self.__security_headers[key][0] = "Found"

	def show_verified_headers(self):
		for header in self.__security_headers:
			print "%s: %s" % (header, self.__security_headers[header][0])

	def verify_url(self, url):
		try:
			header = {"User-Agent":"Mozilla/5.0"}
			req = urllib2.Request(url, headers=header)
			content = urllib2.urlopen(req, timeout = 2)
			ip = socket.gethostbyname(urlparse(content.geturl()).hostname)
			info = content.info()
			request_url = content.geturl()

			print "URL: %s" % request_url
			print "IP: %s\n\nSECURITY HEADERS" % ip
			self.check_headers(info)
			self.show_verified_headers()
			print "\nRAW HEADERS\n%s" % info
			return True

		except (urllib2.URLError, ValueError):
			return False

	def do_search(self, string):
		protocol = [" ", "https://", "http://"]

		for index in range(len(protocol)):
			if self.verify_url("%s%s" % (protocol[index], string)):
				break
			elif index == 2:
				print "Page Not Found."


