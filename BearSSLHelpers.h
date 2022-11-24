/* Modifications were done by Folkert van Heusden to make it work with MyIP. */

/*
   WiFiClientBearSSL- SSL client/server for esp8266 using BearSSL libraries
   - Mostly compatible with Arduino WiFi shield library and standard
   WiFiClient/ServerSecure (except for certificate handling).

   Copyright (c) 2018 Earle F. Philhower, III

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
   */

#ifndef _BEARSSLHELPERS_H
#define _BEARSSLHELPERS_H

#include <bearssl/bearssl.h>

// Internal opaque structures, not needed by user applications
namespace brssl {
	class public_key;
	class private_key;
}

namespace BearSSL {

	// Holds either a single public RSA or EC key for use when BearSSL wants a pubkey.
	// Copies all associated data so no need to keep input PEM/DER keys.
	// All inputs can be either in RAM or PROGMEM.
	class PublicKey {
		public:
			PublicKey();
			PublicKey(const char *pemKey);
			PublicKey(const uint8_t *derKey, size_t derLen);
			~PublicKey();

			bool parse(const char *pemKey);
			bool parse(const uint8_t *derKey, size_t derLen);

			// Accessors for internal use, not needed by apps
			bool isRSA() const;
			bool isEC() const;
			const br_rsa_public_key *getRSA() const;
			const br_ec_public_key *getEC() const;

			// Disable the copy constructor, we're pointer based
			PublicKey(const PublicKey& that) = delete;

		private:
			brssl::public_key *_key;
	};

	// Holds either a single private RSA or EC key for use when BearSSL wants a secretkey.
	// Copies all associated data so no need to keep input PEM/DER keys.
	// All inputs can be either in RAM or PROGMEM.
	class PrivateKey {
		public:
			PrivateKey();
			PrivateKey(const char *pemKey);
			PrivateKey(const uint8_t *derKey, size_t derLen);
			~PrivateKey();

			bool parse(const char *pemKey);
			bool parse(const uint8_t *derKey, size_t derLen);

			// Accessors for internal use, not needed by apps
			bool isRSA() const;
			bool isEC() const;
			const br_rsa_private_key *getRSA() const;
			const br_ec_private_key *getEC() const;

			// Disable the copy constructor, we're pointer based
			PrivateKey(const PrivateKey& that) = delete;

		private:
			brssl::private_key *_key;
	};

	// Holds one or more X.509 certificates and associated trust anchors for
	// use whenever BearSSL needs a cert or TA.  May want to have multiple
	// certs for things like a series of trusted CAs (but check the CertStore class
	// for a more memory efficient way).
	// Copies all associated data so no need to keep input PEM/DER certs.
	// All inputs can be either in RAM or PROGMEM.
	class X509List {
		public:
			X509List();
			X509List(const char *pemCert);
			X509List(const uint8_t *derCert, size_t derLen);
			~X509List();

			bool append(const char *pemCert);
			bool append(const uint8_t *derCert, size_t derLen);

			// Accessors
			size_t getCount() const {
				return _count;
			}
			const br_x509_certificate *getX509Certs() const {
				return _cert;
			}
			const br_x509_trust_anchor *getTrustAnchors() const {
				return _ta;
			}

			// Disable the copy constructor, we're pointer based
			X509List(const X509List& that) = delete;

		private:
			size_t _count;
			br_x509_certificate *_cert;
			br_x509_trust_anchor *_ta;
	};

	// Opaque object which wraps the BearSSL SSL session to make repeated connections
	// significantly faster.  Completely optional.
	class WiFiClientSecure;

	// Cache for a TLS session with a server
	// Use with BearSSL::WiFiClientSecure::setSession
	// to accelerate the TLS handshake
	class Session {
		friend class WiFiClientSecureCtx;

		public:
		Session() { memset(&_session, 0, sizeof(_session)); }
		private:
		br_ssl_session_parameters *getSession() { return &_session; }
		// The actual BearSSL session information
		br_ssl_session_parameters _session;
	};

	// Represents a single server session.
	// Use with BearSSL::ServerSessions.
	typedef uint8_t ServerSession[100];

	// Cache for the TLS sessions of multiple clients.
	// Use with BearSSL::WiFiServerSecure::setCache
	class ServerSessions {
		friend class WiFiClientSecureCtx;

		public:
		// Uses the given buffer to cache the given number of sessions and initializes it.
		ServerSessions(ServerSession *sessions, uint32_t size) : ServerSessions(sessions, size, false) {}

		// Dynamically allocates a cache for the given number of sessions and initializes it.
		// If the allocation of the buffer wasn't successful, the value
		// returned by size() will be 0.
		ServerSessions(uint32_t size) : ServerSessions(size > 0 ? new ServerSession[size] : nullptr, size, true) {}

		~ServerSessions();

		// Returns the number of sessions the cache can hold.
		uint32_t size() { return _size; }

		private:
		ServerSessions(ServerSession *sessions, uint32_t size, bool isDynamic);

		// Returns the cache's vtable or null if the cache has no capacity.
		const br_ssl_session_cache_class **getCache();

		// Size of the store in sessions.
		uint32_t _size;
		// Store where the information for the sessions are stored.
		ServerSession *_store;
		// Whether the store is dynamically allocated.
		// If this is true, the store needs to be freed in the destructor.
		bool _isDynamic;

		// Cache of the server using the _store.
		br_ssl_session_cache_lru _cache;
	};
}

#endif
