# SaltedHashPWD
Simplified Salted-Hash password class

  This project contains 2 classes, the main class (SaltedHashPassword)
    and a test class to demonstrated the usage and functionality (PWDTests.java)
    
	The goal of this class is to have a simplified Salted-Hash password creator and validator
	 It is my belief that the most secure method for the salted hash combo is to have the salt hard coded into your application
	   and store the salted-hash in the database. A sttic method, generateSalt, is included for creating a salt string if you need it.
	
	 Why? if you store the HASH:SALT combo, and a hacker gets access to the database, they now have the hash and the salt
	 	however if the salt is hard coded in your app, and only the result Salted-Hash is stored in your database
	 	the hacker has to get the code, find the salt and get access to your database as well.
	
	 Just having hashed passwords is a great start, it prevents your own users and employees from seeing passwords.
	 It is my opinion that salting a hash is to protect from hackers, and as stated before, if the salt and the hash 
	  are both saved in the database, I believe you are just making your database the only obstacle for hackers.
	
	 Therefore this class assumes that you have the SALT in your code outside of this class.
	 This class is based on the work and ideas of Taylor Hornby taylor@defuse.ca
	   https://github.com/defuse/password-hashing
