class Connection:
	con = {}

	def __init__(self):
		self.con = {}

	def create (self, sock):
		self.con[sock] = ''

	def clear (self, sock):
		t = self.con[sock]
		if sock in self.con.keys(): del self.con[sock]
		if t in self.con.keys(): del self.con[t]

	def add (self, src, dst):
		self.con[src]=dst
		self.con[dst]=src

	def delete (self, sock):
		t = self.con[sock]
		if sock in self.con.keys(): del self.con[sock]
		self.con[t] = ''

	def empty(self, sock):
		return (self.con[sock] == '')

	def lookup (self, sock):
		if self.con[sock] != '':
			return self.con[sock]
		else:
			return sock

	def keys(self):
		return self.con.keys()
