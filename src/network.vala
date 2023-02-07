namespace ProcessInspector {
	public class NetworkService : Object {
		public Soup.Session session {
			get {
				if (_session == null) {
					_session = new Soup.Session ();
					_session.tls_database = new FridaTlsDatabase ();
				}
				return _session;
			}
		}
		private Soup.Session _session;

		public async File download (string url, Cancellable? cancellable) throws Error {
			var msg = new Soup.Message ("GET", url);
			InputStream input_stream = yield session.send_async (msg, Priority.DEFAULT, cancellable);

			FileIOStream tmp_stream;
			var tmp_file = File.new_tmp (null, out tmp_stream);

			yield tmp_stream.output_stream.splice_async (input_stream, CLOSE_SOURCE | CLOSE_TARGET, Priority.DEFAULT, cancellable);

			return tmp_file;
		}
	}

	private class FridaTlsDatabase : TlsDatabase {
		private TlsCertificate frida_certificate;

		construct {
			try {
				frida_certificate = new TlsCertificate.from_pem ("""
-----BEGIN CERTIFICATE-----
MIIHQDCCBiigAwIBAgIRAKaByRupVKJS5lcub3aT60owDQYJKoZIhvcNAQELBQAw
gZAxCzAJBgNVBAYTAkdCMRswGQYDVQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAO
BgNVBAcTB1NhbGZvcmQxGjAYBgNVBAoTEUNPTU9ETyBDQSBMaW1pdGVkMTYwNAYD
VQQDEy1DT01PRE8gUlNBIERvbWFpbiBWYWxpZGF0aW9uIFNlY3VyZSBTZXJ2ZXIg
Q0EwHhcNMTgwNDMwMDAwMDAwWhcNMjAwODAxMjM1OTU5WjBXMSEwHwYDVQQLExhE
b21haW4gQ29udHJvbCBWYWxpZGF0ZWQxHTAbBgNVBAsTFFBvc2l0aXZlU1NMIFdp
bGRjYXJkMRMwEQYDVQQDDAoqLmZyaWRhLnJlMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAxWgJNGabAWfQFRwvFyuXkqMVwUqStQFr6jLIWcsqkb5e4bAu
eSkH2foyZ8Qk3AaDiPKu1GeMz3SXdJfz42IQf8D99dOYej6f6gCmZYRlrINTvF3y
5fizGoieCP0TmjiPP2zQ8kQmM9LNG9Cm5MAaOlQC36WpMjJJeFDV330GGHTix4nY
QzSO32lg6iHVv1da6oZLGx8Ps4CUUmaxzV58riLYgtMiCtoK63n++lwHWgVsvVH6
0hrWNBiaAhrzrxTaXOBx/nNbfUNFHpaTzdXXN9amLl+xO+UWaWy43XMNGbi28N3Q
OdzxvHDy1fvRoeIoysZr1atjurrqc41pqrYxjQIDAQABo4IDyzCCA8cwHwYDVR0j
BBgwFoAUkK9qOpRaC9iQ6hJWc99DtDoo2ucwHQYDVR0OBBYEFC5GNkNRBwjxs2NJ
a4s+IQJLr0vTMA4GA1UdDwEB/wQEAwIFoDAMBgNVHRMBAf8EAjAAMB0GA1UdJQQW
MBQGCCsGAQUFBwMBBggrBgEFBQcDAjBPBgNVHSAESDBGMDoGCysGAQQBsjEBAgIH
MCswKQYIKwYBBQUHAgEWHWh0dHBzOi8vc2VjdXJlLmNvbW9kby5jb20vQ1BTMAgG
BmeBDAECATBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vY3JsLmNvbW9kb2NhLmNv
bS9DT01PRE9SU0FEb21haW5WYWxpZGF0aW9uU2VjdXJlU2VydmVyQ0EuY3JsMIGF
BggrBgEFBQcBAQR5MHcwTwYIKwYBBQUHMAKGQ2h0dHA6Ly9jcnQuY29tb2RvY2Eu
Y29tL0NPTU9ET1JTQURvbWFpblZhbGlkYXRpb25TZWN1cmVTZXJ2ZXJDQS5jcnQw
JAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmNvbW9kb2NhLmNvbTAfBgNVHREEGDAW
ggoqLmZyaWRhLnJlgghmcmlkYS5yZTCCAfYGCisGAQQB1nkCBAIEggHmBIIB4gHg
AHUA7ku9t3XOYLrhQmkfq+GeZqMPfl+wctiDAMR7iXqo/csAAAFjFs5GKQAABAMA
RjBEAiBnQMQ/bvjE7eNGATYxObslEP0D4jMTEdZXq7QH544kcAIgbzSQFV8zKU2V
LOV4jdEr99botMEMHD45kxCNDwNFBXcAdwBep3P531bA57U2SH3QSeAyepGaDISh
EhKEGHWWgXFFWAAAAWMWzkZxAAAEAwBIMEYCIQC3FteqJo6DOHsPz1U7QplbF6jk
AVF1yf3wcNsvclFnAgIhAMbbN56JMmyiv9fFerrV8yJB4ttuDcGLumS7/QArky2E
AHUAVYHUwhaQNgFK6gubVzxT8MDkOHhwJQgXL6OqHQcT0wwAAAFjFs5HZAAABAMA
RjBEAiA19CRDvxg5EIdp6H4R3NAtxRRHrJw/7SeNEhAJ0XqaJgIgLx29dB4PSdgS
COc6EpjRnye/rWH4p6iy+dxpDaExb64AdwCyHgXMi6LNiiBOh2b5K7mKJSBna9r6
cOeySVMt74uQXgAAAWMWzkYqAAAEAwBIMEYCIQC09V8fGYRF+FwJ6iVMldWjDEAk
HeR6xXoIb2WynUX/9QIhANSJc6qFjdf8XkL5wYIoqYUHa/ZVQLA3f9P/D654NMGJ
MA0GCSqGSIb3DQEBCwUAA4IBAQAgWB/B++rXTc/p80jc7pNzQHng2uvu1OW4jm+K
OKN6he0SZZgyIfYzP0y9QcAYbVNcm6o03ZG6dgGLKgeo8FoMqYe3FYK69e0OKojd
j809JGsNtJTHDbBb9scmjm0AHdcFHRu26T11EDkpt9KrezjmutjQ4gwZa1Jt2yS1
m/Ei5pPOyHRWxS5IQ+xfj519PSYyG2NCNUGM7Troiv6VBYxdWSJCRoW+VQ2R7i5s
tx6l0Z5MZr8EzAKdtgeAAV/moYh4Y7E3j1fbKEPOeAQH/pKbEbkWBO+lt0HkmUKv
FiAhoVTrgqgdyIalvvQHr2rv030qjqsB7iY2teoam1l6Hxyp
-----END CERTIFICATE-----
""", -1);
			} catch (Error e) {
				assert_not_reached ();
			}
		}

		public override TlsCertificateFlags verify_chain (TlsCertificate chain, string purpose, SocketConnectable? identity, TlsInteraction? interaction, TlsDatabaseVerifyFlags flags, Cancellable? cancellable) throws Error {
			return chain.is_same (frida_certificate) ? 0 : TlsCertificateFlags.BAD_IDENTITY;
		}
	}
}
