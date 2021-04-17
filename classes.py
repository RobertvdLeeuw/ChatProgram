class User:  # Permissions
	active = False
	currentAddress = 0
	lastMessagedTime = 0

	def __init__(self, name, id, password, address):
		self.name = name
		self.id = id
		self._password = password
		self.active = True
		self.currentAddress = address

	def checkLogin(self, username, password):
		return self.name == username and self._password == password

	def login(self, address):
		self.active = True
		self.currentAddress = address

	def logout(self):
		self.active = False
		self.currentAddress = 0

	def changeName(self, name):
		self.name = name

	def changeName(self, password):
		self._password = password


class SuperUser(User):
	def ban(self, user):
		pass

	def kick(self, user):
		pass

	def promote(self, user):
		pass

	def demote(self, superuser):
		pass

	def restrict(self, user):
		pass
