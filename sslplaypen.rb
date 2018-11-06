#!/usr/bin/env ruby -w

require 'termios'
require 'highline/import'
require 'openssl'
require 'base64'

include OpenSSL

class Tools
	def initialize()
		@ca_file=""
		@ca_key_file=""
		@ca_key_plain_file=""
		@subca_file=""
		@subca_key_file=""
		@subca_key_plain_file=""
		@client_file=""
		@client_key_file=""
		@crl_file=""
		@responder_file=""
		@responder_key_file=""
		@ocspreq_file=""
		@ee_file=""

		@keytype="rsa"
		@privkey=0
		@pubkey=0
		@key=0
		@iv=0
		@cipher=nil
		@hash="sha1"
		@csr=""
		@serialno=0
	end

	def passwd_cb() # =  Proc.new{
		flag=false	# change to TRUE!!!!
		print "Enter password: "
		pass = $stdin.gets.chop!

		if flag
		   print "Verify password: "
		   pass2 = $stdin.gets.chop!
		   raise "verify failed." if pass != pass2
		end
		pass
	end

# Private Key Tools
	def privkeymenu()
		say "\nPrivate Key Crypto Menu\n"
		choices=%w{"Generate Key" "Encrypt String" "Decrypt String" "Show Key" "Show IV" Quit}

		choose do |menu|
			menu.choice :"Generate Key" do privgenkey() end
			menu.choice :"Encrypt String" do privencrypt() end
			menu.choice :"Decrypt String" do privdecrypt() end
			menu.choice :"Show Key" do privshowkey() end
			menu.choice :"Show IV" do privshowiv() end
			menu.choice :Quit 
		end
	end

	def privgenkey()
		puts "Enter Key Size [128|192|256|...]"
		size = /\n/.match(gets()).pre_match().to_i
		@key=OpenSSL::Random.random_bytes(size/8){ putc "." }
		puts
		puts "#{size}-bit Key generated"
		privkeymenu()
	end

	def privencrypt()
		if @key==0
			@key=OpenSSL::Random.random_bytes(128/8){ putc "." }
			#@key=OpenSSL::Random.random_bytes(size/8){ putc "." }
		end
		
		string="The cat sat on the mat!"
		c=OpenSSL::Cipher::Cipher.new("aes-128-cbc")
		c.encrypt
		c.key = @key
		c.iv=@iv=@iv=c.random_iv
		#c.pass=pkcs5_keyivgen("password") - no longer supported!
		e=c.update(string)
		e << c.final

		cipherfile=File.new("ciphertext","w+")
		keyfile=File.new("keyfile","wb")
		ivfile=File.new("ivfile","wb")
		keyfile << @key
		ivfile << @iv
		puts "Plaintext: #{string}"
		puts "Ciphertext: #{e.to_s}"
		cipherfile << Base64.encode64(e)
		cipherfile.flush()
		privkeymenu()
	end

	def privdecrypt()
		data=File.open("ciphertext","r+").gets()
		str=Base64.decode64(data)
		puts "Ciphertext: #{str.to_s}"

		if @iv==0
			@iv=File.open("ivfile","rb").gets()
		end

		if @key==0
			@key=File.open("keyfile","rb").gets()
		end

		dec=OpenSSL::Cipher::Cipher.new("aes-128-cbc")
		dec.decrypt
		dec.key = @key
		dec.iv=@iv
		d=dec.update(str)
		d << dec.final
		puts "Decrypted #{d}\n"
		privkeymenu()

		rescue Errno::ENOENT => e
			$stderr.puts("< File not found!!!\n")
			privkeymenu()
	end

	def privshowkey()
		puts "\nKey: #{@key}\n\n"
		privkeymenu()
	end

	def privshowiv()
		puts "\nIV: #{@iv}\n\n"
		privkeymenu()
	end

# Public Key Tools
	def pubkeymenu()
		say "\nPublic Key Crypto Menu\n"
		choices=%w{"Choose Algorithm" "Generate Key Pair" "Signing/Verifying" "Encryption" "Decryption" "Export Keys" Quit}

		choose do |menu|
			menu.choice :"Choose Algorithm" do choosepubalgo() end
			menu.choice :"Generate Key Pair" do pubgenkey() end
			menu.choice :"Signing/Verifying" do signverify() end
			menu.choice :"Encryption" do pubencrypt() end
			menu.choice :"Decryption" do pubdecrypt() end
			menu.choice :"Export Keys" do pubkeyexport() end
			menu.choice :"Display Keys" do pubdisplay() end
			menu.choice :Quit 
		end
	end

	def choosepubalgo()
		say "\nPublic Key Crypto Menu\n"
		choices=%w{"RSA" "DSA" "Diffie-Hellmann"}

		choose do |menu|
			menu.choice :"RSA" do @keytype="rsa" end
			menu.choice :"DSA" do @keytype="dsa" end
			menu.choice :"Diffie-Hellmann" do @keytype="dh" end
		end
# RSA | DSA | DH
		pubkeymenu()
	end

	def pubgenkey()
		puts "Enter Key Size [512|1024|2048|...]"
		size = /\n/.match(gets()).pre_match().to_i
		@privkey=OpenSSL::PKey::RSA.new(size,exponent=65537) if @keytype=="rsa"
		@privkey=OpenSSL::PKey::DSA.new(size,exponent=65537) if @keytype=="dsa"
		@privkey=OpenSSL::PKey::DH.new(size,exponent=65537) if @keytype=="dh"
		@pubkey=@privkey.public_key
		puts "#{size}-bit Key generated"
		pubkeymenu()
	end

	def signverify()
		puts "<< Sign/Verify"
		#text="The cat sat on the mat!"
  		puts "\nEnter Text File\n\n" 
		file = /\n/.match(gets()).pre_match()
		text=File.open(file,"r").read()
		sig=@privkey.sign(OpenSSL::Digest::SHA1.new,text)
		puts "\nPlaintext: #{text}\n"
		puts "Signature: #{sig}\n"
		puts "Verify: #{@privkey.verify(OpenSSL::Digest::SHA1.new,sig,text)}\n"
		pubkeymenu()

		rescue Errno::ENOENT => e
			$stderr.puts("< Textfile not found!!!\n")
			pubkeymenu()
	end

	def pubencrypt()
		puts "<< Pubencrypt"
		#text="The cat sat on the mat!"
  		puts "\nEnter Text File\n\n" 
		file = /\n/.match(gets()).pre_match()
		text=File.open(file,"r").read()
		@cipher=@privkey.public_encrypt(text)
		puts "\nPlaintext: #{text}\n"
		puts "Encrypted: #{@cipher}\n"
		pubkeymenu()

		rescue Errno::ENOENT => e
			$stderr.puts("< Textfile not found!!!\n")
			pubkeymenu()
	end

	def pubdecrypt()
		puts "<< Pubdecrypt"
		puts "Encrypted: #{@cipher}\n"
		text=@privkey.private_decrypt(@cipher)
		puts "\nPlaintext: #{text}\n"
		pubkeymenu()
	end

	def pubkeyexport()
		puts "<< Pubexport"
		say "\nPublic Key Export Menu\n"

		choices=%w{"DER Format" "PEM Format" Quit}

		choose do |menu|
			menu.choice :"DER Format" do printder() end
			menu.choice :"PEM Format" do printpem() end 
			menu.choice :Quit do pubkeymenu() end
		end
		pubkeymenu()
	end

	def printder()
		if @privkey==0
			puts "Enter Keyfile:\n"
			@keyfile = /\n/.match(gets()).pre_match()
			puts @keyfile.to_der
		else
			puts @privkey.to_der
		end
		pubkeyexport()
	end

	def printpem()
		if @privkey==0
			puts "Enter Keyfile:\n"
			@keyfile = /\n/.match(gets()).pre_match()
			puts @keyfile.to_pem
		else
			puts @privkey.to_pem
		end
		pubkeyexport()
	end

	def pubdisplay()
		puts "Private Key:\n#{@privkey}\n"
		puts "Public Key\n:#{@pubkey}\n"
		pubkeymenu()
	end

# Hashing Menu
	def hashmenu()
		say "\nHash Menu\n"

		choices=%w{"Choose Hash Algorithm\n" "Hash String" "Hash File" Quit}

		choose do |menu|
			menu.choice :"Choose Hash Algorithm" do choosehash() end
			menu.choice :"Hash String" do hashstring() end
			menu.choice :"Hash File" do hashfile() end
			menu.choice :Quit 
		end
	end

	def choosehash()
		say "\nChoose Hash Algorithm\n"

		choices=%w{"Choose Hash Algorithm\n" "Hash String" "Hash File" Quit}

		choose do |menu|
			menu.choice :"MD2" do @hash="MD2" end
			menu.choice :"MD4" do @hash="MD4" end
			menu.choice :"MD5" do @hash="MD5" end
			menu.choice :"SHA-1" do @hash="SHA1" end
			menu.choice :"DSS" do @hash="DSS" end
			menu.choice :"MDC2" do @hash="MDC2" end
			menu.choice :"RIPEMD160" do @hash="RIPEMD160" end
			menu.choice :Quit 
		end
		hashmenu()
	end

	def hashstring()
		#string="The cat sat on the mat!"
  		puts "<< Enter Hash String\n\n" 
		text = /\n/.match(gets()).pre_match()
		case
			when @hash="MD2"
				digest=OpenSSL::Digest::MD2.new(text)
			when @hash="MD4"	 	
				digest=OpenSSL::Digest::MD4.new(text)
			when @hash="MD5"
				digest=OpenSSL::Digest::MD5.new(text)
			when @hash="SHA1"
				digest=OpenSSL::Digest::SHA1.new(text)
			when @hash="DSS"
				digest=OpenSSL::Digest::DSS.new(text)
			when @hash="MDC2"
				digest=OpenSSL::Digest::MDC2.new(text)
			when @hash="RIPEMD160"
				digest=OpenSSL::Digest::RIPEMD160.new(text)
		end
		puts "\nPlaintext: #{text}"
		puts "Digest: #{digest}"
		hashmenu()
	end

	def hashfile()
  		puts "<< Hash wFile\n\n" 
		#string="The cat sat on the mat!"
  		puts "\nEnter Hash File\n\n" 
		file = /\n/.match(gets()).pre_match()
		text=File.open(file,"r").read()
		digest=OpenSSL::Digest::SHA1.new(text)
		puts "\nPlaintext: #{text}"
		puts "Digest: #{digest}"
		hashmenu()
	end

# Certificate Tools
	def genca()
		puts "\n<< Generate CA Certificate\n\n"

		puts "Generating CA key: "
		key=PKey::RSA.new(2048){ putc "." }
		putc "\n"
		putc "\n"

		cert=X509::Certificate.new()

		puts "Enter DN Name (e.g. /C=GB/L=London/O=SBC/OU=Test/CN=Romek):"
		name_str = /\n/.match(gets()).pre_match()
		name = name_str.scan(/\/([^\/]+)/).collect { |i| i[0].split("=") }

		cert.subject=cert.issuer=X509::Name.new(name)
		cert.not_before = Time.now
		cert.not_after = Time.now + 2 * 365 * 24 * 60 * 60
		cert.public_key=key
		cert.serial=0
		cert.version=2
		
		key_usage = ["cRLSign", "keyCertSign"]
		ext = []
		ef = X509::ExtensionFactory.new
		ef.subject_certificate = cert
		ext << ef.create_extension("basicConstraints", "CA:TRUE", true)
		ext << ef.create_extension("keyUsage", key_usage.join(","), true)
		ext << ef.create_extension("nsComment","Generated by OpenSSL for Ruby.")
		ext << ef.create_extension("subjectKeyIdentifier", "hash")
		cert.extensions = ext
		ef.issuer_certificate = cert # we needed subjectKeyInfo inside, now we have it
		ext_auth_key_id =
		  ef.create_extension("authorityKeyIdentifier", "keyid:always,issuer:always")
		cert.add_extension(ext_auth_key_id)
		cert.sign(key, Digest::SHA1.new)

		puts "Enter CA Certificate File (e.g. ca1.crt):"
		@ca_file = /\n/.match(gets()).pre_match()

		puts "Writing #{@ca_file}."
		File.open(@ca_file, "w") do |f|
			f.write cert.to_pem
		end

	# If needed, export private key in plaintext. 131107 RS
		# puts "Enter Key Plaintext File:"
		# @ca_key_plain_file = /\n/.match(gets()).pre_match()

		# puts "Writing #{@ca_key_plain_file}."
		# File.open(@ca_key_plain_file, "w", 0400) do |f|
		#   f << key.to_pem
		# end

		puts "Enter Private Key File (eg. cakey1.pem):"
		@ca_key_file = /\n/.match(gets()).pre_match()

		puts "Writing #{@ca_key_file}."
		File.open(@ca_key_file, "w") do |f|
		  f << key.export(Cipher::DES.new(:EDE3, :CBC), passwd_cb())
		end

		puts "DONE. (Generated certificate for '#{cert.subject}')"
		certmenu()
	end

	def gensubca()
		puts "\nGenerate Sub-CA Certificate\n\n"
# num (serialno), csr to be supplied somehow.

		if @ca_file==""
			puts "Enter CA Certificate File:"
			@ca_file = /\n/.match(gets()).pre_match()
		end

		puts "Reading CA cert from #{@ca_file}"
		ca=X509::Certificate.new(File.read(@ca_file))

		if @ca_key_file==""
			puts "Enter CA Key File:"
			@ca_key_file = /\n/.match(gets()).pre_match()
		end

		puts "Reading CA key from #{@ca_key_file}"
		@ca_key=PKey::RSA.new(File.read(@ca_key_file),passwd_cb())

		if @csr==""
			puts "Enter CSR File:"
			@csr = /\n/.match(gets()).pre_match()
		end

		puts "Reading CSR from #{@csr}"
		req=X509::Request.new(File.read(@csr))

		if @serialno==0
			puts "Enter Serial Number for Certificate:"
			@serialno = /\n/.match(gets()).pre_match()
		end
		num=@serialno.to_i
		
		cert=X509::Certificate.new
		cert.subject = req.subject
		cert.issuer = ca.subject
		cert.not_before = Time.now
		cert.not_after = Time.now + 365 * 24 * 60 * 60
		cert.public_key = req.public_key
		cert.serial = num 
		cert.version = 2

		keyusage=[]
		extkeyusage=[]

		ext = []
		ef = X509::ExtensionFactory.new
		ef.subject_certificate = cert
		ef.issuer_certificate = ca
		keyusage << "cRLSign" << "keyCertSign"
		ext << ef.create_extension("basicConstraints", "CA:TRUE,pathlen:0", true)
		ext << ef.create_extension("keyUsage", keyusage.join(","), true)

		if extkeyusage.size > 0
			ext << ef.create.extension("extendedKeyUsage",extkeyusage.join(","),false)
		end
		ext << ef.create_extension("nsComment","Generated by OpenSSL for Ruby.")
		ext << ef.create_extension("subjectKeyIdentifier", "hash")
		ext << ef.create_extension("authorityKeyIdentifier", "keyid:always,issuer:always")
		cert.sign(@ca_key, Digest::SHA1.new)

		puts "Enter SubCA Certificate File:"
		@subca_file = /\n/.match(gets()).pre_match()

		puts "Writing #{@subca_file}."
		File.open(@subca_file, "w") do |f|
			f.write cert.to_pem
		end

		puts "DONE. (Generated certificate for '#{cert.subject}')"
		certmenu()
	end

	def genclient()

		if @ca_file==""
			puts "Enter CA Certificate File:"
			@ca_file = /\n/.match(gets()).pre_match()
		end

		puts "Reading CA cert from #{@ca_file}"
		ca=X509::Certificate.new(File.read(@ca_file))

		if @ca_key_file==""
			puts "Enter CA Key File:"
			@ca_key_file = /\n/.match(gets()).pre_match()
		end

		puts "Reading CA key from #{@ca_key_file}"
		ca_key=PKey::RSA.new(File.read(@ca_key_file),passwd_cb())

		if @csr==""
			puts "Enter CSR File:"
			@csr = /\n/.match(gets()).pre_match()
		end

		puts "Reading CSR from #{@csr}"
		req=X509::Request.new(File.read(@csr))

		if @serialno==0
			puts "Enter Serial Number for Certificate:"
			@serialno = /\n/.match(gets()).pre_match()
		end
		num=@serialno.to_i
		
		cert=X509::Certificate.new
		cert.subject = req.subject
		cert.issuer = ca.subject
		cert.not_before = Time.now
		cert.not_after = Time.now + 365 * 24 * 60 * 60
		cert.public_key = req.public_key
		cert.serial = num
		cert.version = 2

		keyusage=[]
		extkeyusage=[]

		ext = []
		ef = X509::ExtensionFactory.new
		ef.subject_certificate = cert
		ef.issuer_certificate = ca
#if cert is server
#		ext << ef.create_extension("basicConstraints", "CA:FALSE", true)
#		keyusage << "cRLSign" << "keyCertSign"
#		extkeyusage << "serverAuth"
#if cert is client
		keyusage << "nonRepudiation" << "digitalSignature" << "keyEncipherment"
		extkeyusage << "clientAuth" << "emailProtection"
#if cert is ocsp
#		ext << ef.create_extension("basicConstraints", "CA:FALSE", true)
		keyusage << "nonRepudiation" << "digitalSignature"
		extkeyusage << "serverAuth" << "OCSPSigning"

		ext << ef.create_extension("basicConstraints", "CA:FALSE", true)
		ext << ef.create_extension("nsComment","Generated by OpenSSL for Ruby.")
		ext << ef.create_extension("keyUsage", keyusage.join(",")) unless keyusage.empty?
		#ext << ef.create.extension("extendedKeyUsage", extkeyusage.join(",")) unless extkeyusage.empty?
		ext << ef.create_extension("subjectKeyIdentifier", "hash")
		ext << ef.create_extension("authorityKeyIdentifier", "keyid:always,issuer:always")
#		ext << ef.create_extension("crlDistributionPoints", "hash")
#		ext << ef.create_extension("authorityInfoAccess", "hash")
		cert.sign(ca_key, Digest::SHA1.new)

		puts "Enter Client Certificate File:"
		@client_file = /\n/.match(gets()).pre_match()

		puts "Writing #{@client_file}."
		File.open(@client_file, "w") do |f|
			f.write cert.to_pem
		end

		puts "DONE. (Generated certificate for '#{cert.subject}')"
		certmenu()
	end

	def gencrl()
		puts "\nGenerate CRL\n\n"

		if @ca_file==""
			puts "Enter CA Certificate File:"
			@ca_file = /\n/.match(gets()).pre_match()
		end

		puts "Reading CA cert (from #{@ca_file})"
		ca = X509::Certificate.new(File.read(@ca_file))

		puts "Enter Private Key File:"
		@ca_key_file = /\n/.match(gets()).pre_match()

		puts "Reading CA key (from #{@ca_key_file})"
		ca_key = PKey::RSA.new(File.read(@ca_key_file), passwd_cb())

		crl = X509::CRL.new
		crl.issuer = ca.issuer
		crl.last_update = Time.now
		crl.next_update = Time.now + 14 * 24 * 60 * 60

#		ARGV.each do |file|
#		  cert = X509::Certificate.new(File.read(file))
#		  re = X509::Revoked.new
#		  re.serial = cert.serial
#		  re.time = Time.now
#		  crl.add_revoked(re)
#		  puts "+ Serial ##{re.serial} - revoked at #{re.time}"
#		end

		crl.sign(ca_key, Digest::MD5.new)

		puts "Enter CRL File:"
		@crl_file = /\n/.match(gets()).pre_match()
		puts "Writing #{@crl_file}."
		File.open(@crl_file, "w") do |f|
			f << crl.to_pem
		end

		puts "DONE. (Generated CRL for '#{ca.subject}')"
		certmenu()
	end

	def displaymenu()
		say "\nCertificate Display\n\n"
		
		choices=%w{"Display Certificate" "Display CRL" Quit}

		choose do |menu|
			menu.choice :"Display Certificate" do displaycert() end
			menu.choice :"Display CRL" do displaycrl() end
			menu.choice :Quit 
		end
	end

	def displaycert()
 		puts "\nCertificate\n\n"
		puts "Enter Certificate File:"
		certfile = /\n/.match(gets()).pre_match()

		puts "Reading CA cert from #{certfile}"
		cert=X509::Certificate.new(File.read(certfile))

		puts cert.to_text
		certmenu()
	end

	def displaycrl()
  		puts "\nCRL\n\n"
		puts "Enter CRL File:"
		crlfile = /\n/.match(gets()).pre_match()

		puts "Reading CA cert from #{crlfile}"
		crl=X509::CRL.new(File.read(crlfile))
		
		puts crl.to_text
		puts
		certmenu()
	end

	def certmenu()
		say "\nCertificate Menu\n"

		choices=%w{"Generate CA Certificate" "Generate Sub-CA Certificate" "Generate Client Certificate" "Generate CRL" "View Certificate/CRL" Quit}

		choose do |menu|
			menu.choice :"Generate CA Certificate" do genca() end
			menu.choice :"Generate Sub-CA Certificate" do gensubca() end
			menu.choice :"Generate Client Certificate" do genclient() end
			menu.choice :"Generate CRL" do gencrl() end
			menu.choice :"View Certificate/CRL" do displaymenu() end
			menu.choice :Quit 
		end
	end

# OCSP Tools
	def ocspreq()
		puts "\nGenerate OCSP Request\n\n"

		if @ca_file==""
			puts "Enter CA Certificate File:"
			@ca_file = /\n/.match(gets()).pre_match()
		end

		puts "Reading CA cert (from #{@ca_file})"
		ca = X509::Certificate.new(File.read(@ca_file))

		if @client_file==""
			puts "Enter Client Certificate File:"
			@client_file = /\n/.match(gets()).pre_match()
		end

		puts "Reading Client Certificate (from #{@client_file})"
		client = X509::Certificate.new(File::read(@client_file))

		if @client_key_file==""
			puts "Enter Client Key File:"
			@client_key_file = /\n/.match(gets()).pre_match()
		end

		puts "Reading Client Key from #{@client_key_file}"
		client_key=PKey::RSA.new(File.read(@client_key_file),passwd_cb())

# End of Initialisation

		req = OCSP::Request.new
		cid = OCSP::CertificateId.new(ee, ca)
		req.add_certid(cid)
		req.add_nonce
		req.sign(client, client_key, [client])
		req_der = req.to_der

		puts "Enter OCSP Request File:"
		@ocspreq_file = /\n/.match(gets()).pre_match()
		puts "Writing #{@ocspreq_file}."
		File.open(@ocspreq_file, "w") do |f|
			f << req.to_der
		end

		puts "\nGenerate OCSP Request\n\n"
		ocspmenu()
	end

	def ocspresp()
		puts "\nGenerate OCSP Response\n\n"

		if @ca_file==""
			puts "Enter CA Certificate File:"
			@ca_file = /\n/.match(gets()).pre_match()
		end

		puts "Reading CA cert (from #{@ca_file})"
		ca = X509::Certificate.new(File.read(@ca_file))

		#if @crl_file==""
		#	puts "Enter CRL File:"
		#	@crl_file = /\n/.match(gets()).pre_match()
		#end

		#puts "Reading CRL (from #{@crl_file})"
		#crl = X509::CRL.new(File.read(@crl_file))

		if @client_file==""
			puts "Enter Client Certificate File:"
			@client_file = /\n/.match(gets()).pre_match()
		end

		puts "Reading Client Certificate (from #{@client_file})"
		client = X509::Certificate.new(File::read(@client_file))

		if @responder_file==""
			puts "Enter Responder Certificate File:"
			@responder_file = /\n/.match(gets()).pre_match()
		end

		puts "Reading Responder from #{@responder_file}"
		responder = X509::Certificate.new(File::read(@responder_file))

		if @responder_key_file==""
			puts "Enter Responder Key File:"
			@responder_key_file = /\n/.match(gets()).pre_match()
		end

		puts "Reading Responder Key from #{@responder_key_file}"
		responder_key=PKey::RSA.new(File.read(@responder_key_file),passwd_cb())

		if @ee_file==""
			puts "Enter End Entity Certificate File:"
			@ee_file = /\n/.match(gets()).pre_match()
		end

		puts "Reading End Entity Certificate from #{@ee_file}"
		ee = X509::Certificate.new(File::read(@ee_file))

		if @ocspreq_file==""
			puts "Enter OCSP Request File:"
			@ocspreq_file = /\n/.match(gets()).pre_match()
		end

		puts "Reading OCSP Request from #{@ocspreq_file}"
		req = OCSP::Request.new(File::read(@ocspreq_file))
		cid= OCSP::CertificateId.new(responder,ca)
		myid= OCSP::CertificateId.new(responder,ca)
		res= nil
# End of Initialisation
puts "End of Initialisation"

		thisupdate = Time.now
		nextupdate = Time.now + 3600

		basic = OCSP::BasicResponse.new()
		basic.copy_nonce(req)

		req.certid.each{|id|
			unless  id.cmp_issuer(myid)
				puts "ocsreq:#{cid}"

				basic.add_status(cid, OCSP::V_CERTSTATUS_UNKNOWN, 0, nil,
					thisupdate, nextupdate, nil)
				#next
    	end

		puts "serial #{id.serial} is good certificate? [Y/n]:"

		answer = $stdin.gets
 		answer.chomp!
		if answer.empty? || /^y/i =~ answer
			puts "Status good"
			basic.add_status(cid, OCSP::V_CERTSTATUS_GOOD, 0, nil,
				thisupdate, nextupdate, nil)
		else
			revoked = Time.now - 3600
			puts "Status revoked"
      	basic.add_status(cid, OCSP::V_CERTSTATUS_REVOKED,
				OCSP::REVOKED_STATUS_KEYCOMPROMISE, revoked,
            	thisupdate, nextupdate, nil)
		end
	}

	# Response status:
		basic.sign(responder, responder_key, [responder])
		res = OCSP::Response.create(OCSP::RESPONSE_STATUS_SUCCESSFUL, basic)

		puts "Enter OCSP Response File:"
		ocspresp_file = /\n/.match(gets()).pre_match()
		puts "Writing #{ocspresp_file}."
		File.open(ocspresp_file, "w") do |f|
			f << res.to_der
		end

		puts "<<End of OCSP Response"
		ocspmenu()
	end

	def ocspshowreq()
	end

	def ocspshowresp()
	end

	def ocspmenu()
		say "\nOCSP Menu\n"

		choices=%w{"Generate OCSP Request" "Generate OCSP Response" "Display Request" "Display Response" Quit}

		choose do |menu|
			menu.choice :"Generate OCSP Request" do ocspreq() end
			menu.choice :"Generate OCSP Response" do ocspresp() end
			menu.choice :"Display Request" do ocspshowreq() end
			menu.choice :"Display Response" do ocspshowreq() end
			menu.choice :Quit 
		end
	end

# PKCS 7 Tools
	def pkcs7menu()
		say "\nPKCS7 Menu\n"

		choices=%w{"PKCS7 Signed Message" "PKCS7 Encrypt Messages" Quit}

		choose do |menu|
			menu.choice :"PKCS7 Signed Message" do pkcs7create() end
			menu.choice :"PKCS7 Encrypt Messages" do pkcs7encrypt() end
			menu.choice :Quit 
		end
	end

	def pkcs7create()
		puts "\nPKCS7 Create\n\n"

		if @ca_file==""
			puts "Enter CA Certificate File:"
			@ca_file = /\n/.match(gets()).pre_match()
		end

		puts "Reading CA cert (from #{@ca_file})"
		ca = X509::Certificate.new(File.read(@ca_file))

		if @crl_file==""
			puts "Enter CRL File:"
			@crl_file = /\n/.match(gets()).pre_match()
		end

		puts "Reading CRL (from #{@crl_file})"
		crl = X509::CRL.new(File.read(@crl_file))

		if @client_file==""
			puts "Enter Client Certificate File:"
			@client_file = /\n/.match(gets()).pre_match()
		end

		puts "Reading Client Certificate (from #{@client_file})"
		client = X509::Certificate.new(File::read(@client_file))

		if @client_key_file==""
			puts "Enter Client Key File:"
			@client_key_file = /\n/.match(gets()).pre_match()
		end

		puts "Reading Client Key from #{@client_key_file}"
		client_key=PKey::RSA.new(File.read(@client_key_file),passwd_cb())

		flags = 0
		smime=0
		#data="The cat sat on the mat!"
		puts "Enter Data File:"
		datafile = /\n/.match(gets()).pre_match()

		puts "Reading Data from #{datafile}"
		data=File.read(datafile)

		p7=PKCS7::PKCS7.new
		#p7.type= :signed
		#p7.detached= true
		#p7.add_certificate(ca)
		#p7.add_crl(crl)
		#p7.add_certificate(client)
		#p7.add_signer(PKCS7::Signer.new(client,client_key, Digest::Digest.new("SHA1")))
		#p7.add_data(data)

		#puts "str:"
		#puts (str=p7.to_pem)

		p7=PKCS7::sign(client,client_key,data)
		#smime=PKCS7::write_smime(p7,data,flags)

		puts "Enter Signed PKCS 7 File:"
		smimefile = /\n/.match(gets()).pre_match()
		puts "Writing #{smimefile}."
		File.open(smimefile, "w") do |f|
			f.write p7.to_pem
		end
	
		puts "<< Create PKCS7 Done"
		pkcs7menu()

		rescue Errno::ENOENT => e
			$stderr.puts("< File not found!!!\n")
			pkcs7menu()
	end

	def pkcs7encrypt()
		puts "\nPKCS7 Encrypt\n"
		flags = 0
		
		puts "Enter Data File:"
		datafile = /\n/.match(gets()).pre_match()

		puts "Reading Data from #{datafile}"
		data=File.read(datafile)

		#flags |= PKCS::TEXT
		cipher = Cipher::Cipher::new("DES-EDE3-CBC")
		
		if @client_file==""
			puts "Enter Client Certificate File:"
			@client_file = /\n/.match(gets()).pre_match()
		end

		puts "Reading Client Certificate (from #{@client_file})"
		client = X509::Certificate.new(File::read(@client_file))

		p7=PKCS7::encrypt([client],data,cipher,flags)

		puts "Enter Encrypted PKCS 7 File:"
		sencfile = /\n/.match(gets()).pre_match()
		puts "Writing #{sencfile}."
		File.open(sencfile, "w") do |f|
			f.write p7.to_der
		end
	
		if @client_key_file==""
			puts "Enter Client Key File:"
			@client_key_file = /\n/.match(gets()).pre_match()
		end

		puts "Reading Client Key from #{@client_key_file}"
		client_key=PKey::RSA.new(File.read(@client_key_file),passwd_cb())

		puts "Decrypting gives...."
		string=p7.decrypt(client_key,client,0)
		puts string
		puts "<< Encrypt PKCS7 Done"
		pkcs7menu()

		rescue Errno::ENOENT => e
			$stderr.puts("< File not found!!!\n")
			pkcs7menu()
	end

	def pkcs7decrypt()
		puts "<< NOT CURRENTLY WORKING, But should! 161107 RS \n"
		puts "<< PKCS7 Decrypt\n"
		flags=0
		cipher = Cipher::Cipher::new("DES-EDE3-CBC")
		p7=PKCS7::PKCS7.new

		if @client_file==""
			puts "Enter Client Certificate File:"
			@client_file = /\n/.match(gets()).pre_match()
		end

		puts "Reading Client Certificate (from #{@client_file})"
		client = X509::Certificate.new(File::read(@client_file))

		if @client_key_file==""
			puts "Enter Client Key File:"
			@client_key_file = /\n/.match(gets()).pre_match()
		end

		puts "Reading Client Key from #{@client_key_file}"
		client_key=PKey::RSA.new(File.read(@client_key_file),passwd_cb())

		puts "Enter Data File:"
		datafile = /\n/.match(gets()).pre_match()

		puts "Reading Data from #{datafile}"
		string=File.read(datafile)

		string=p7.decrypt(client_key,client,0)
		puts string
	end

	def pkcs11menu()
		puts "\nPKCS11 Menu\n\n"
		puts "How do we incorporate a pkcs#11 library and why aren't there any?\n"
	end
end

class Menu
	def initialize
		say "\n\nCryptographic Generic Toolkit\n"
		tools=Tools.new()
		choices=%w{"Private Key Crypto Menu" "Public Key Crypto Menu" "Hash Menu" "Certificate Menu" "OCSP Menu" "PKCS 7 Menu" "View Certificate" Quit}
		say "\n"
		choose do |menu|
			say("Tools Menu\n")
			menu.choice :"Private Key Crypto Menu" do tools.privkeymenu() end
			menu.choice :"Public Key Crypto Menu" do tools.pubkeymenu() end
			menu.choice :"Hash Menu" do tools.hashmenu() end
			menu.choice :"Certificate Menu" do tools.certmenu() end
			menu.choice :"OCSP Menu" do tools.ocspmenu() end
			menu.choice :"PKCS7 Menu" do tools.pkcs7menu() end
			#menu.choice :"PKCS11 Menu" do tools.pkcs11menu() end
			menu.choice :"View Certificate" do tools.displaymenu() end
			menu.choice :Quit do quit() end
		end
	end

	def quit()
		puts "Quit"
	end
end

Menu.new
