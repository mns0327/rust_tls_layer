.PHONY: run

install:
	openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes

run:
	openssl s_server -accept 4433 -cert cert.pem -key key.pem -cipher AES128-GCM-SHA256 -tls1_2 -debug -state -msg
