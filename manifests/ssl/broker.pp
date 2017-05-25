# Provides support for SSL and SSL authentication in Kafka, including generation
# of the Java keystores.
#
# Usage:
#
# Requires a pre-build CA key and cert saved in Hiera. You can generate one
# with:
#  openssl req \
#  -new \
#  -nodes \
#  -x509 \
#  -keyout ${ssl_dir}/ca.key \
#  -out ${ssl_dir}/ca.crt  \
#  -days ${ssl_validity_days} \
#  -subj "/C=US/ST=Kafka/L=Kafka/O=Kafka/OU=Kafka/CN=kafka.internal"
#
#
# The following must be set in Hiera:
#
# kafka::ssl::broker::ca_cert: |
#   <contents of cert>
# kafka::ssl::broker::ca_key: |
#   <contents of key>
#
# kafka::broker::config:
#   # Ensure listening/advertising on the SSL port. Can look something like this:
#   listeners: "SSL://0.0.0.0:9093"
#   advertised.listeners: "SSL://%{facts.fqdn}:9093"
#
#   # Configure the key and cert used by this broker.
#   ssl.keystore.location: /etc/pki/kafka/%{facts.hostname}.keystore.jks
#   ssl.keystore.password: password
#   ssl.key.password: password
#
#   # Configure the CA we trust.
#   ssl.truststore.location: /etc/pki/kafka/ca.truststore.jks
#   ssl.truststore.password: password
#
#   # Optional - If you want to do SSL client authentication and block any
#   # clients that have not been signed by the CA.
#   ssl.client.auth: required
#
#
class kafka::ssl::broker (
  $ssl_dir                = $kafka::params::ssl_dir,
  $ssl_validity_days      = $kafka::params::ssl_validity_days,
  $ssl_keystore_password  = $kafka::params::ssl_keystore_password,
  $group                  = $kafka::params::group,
  $user                   = $kafka::params::user,

  # CA cert & key - must be supplied as per comments at top.
  $ca_cert,
  $ca_key,

  ) inherits kafka::params {

  # Ensure the broker is installed first, thus creating user directories and
  # ensuring that Java is present on the server.
  require ::kafka::broker::install

  # Set some sensible defaults in this class
  File {
    owner   => $user,
    group   => $group,
  }

  Exec {
    path => '/bin:/sbin:/usr/bin:/usr/sbin',
    cwd  => $ssl_dir,
  }


  # Create the directories to store our certs
  file { $ssl_dir:
    ensure  => 'directory',
    mode    => '0700',
  } ->

  file { "${ssl_dir}/clients":
    ensure  => 'directory',
    mode    => '0700',
  } ->

  file { "${ssl_dir}/dist":
    ensure  => 'directory',
    mode    => '0700',
  } ->

  # Install the CA cert
  file { "${ssl_dir}/ca.crt":
    ensure  => 'file',
    mode    => '0600',
    content => $ca_cert,
  } ->

  file { "${ssl_dir}/ca.key":
    ensure  => 'file',
    mode    => '0600',
    content => $ca_key,
  } ->

  # Generate a Java keystore "truststore" with the CA cert we have in PEM format.
  exec { "ca_truststore":
    command => "keytool -keystore ${ssl_dir}/ca.truststore.jks -storepass ${ssl_keystore_password} -keypass ${ssl_keystore_password} -alias CARoot -import -file ${ssl_dir}/ca.crt -noprompt",
    creates => "${ssl_dir}/ca.truststore.jks",
  } ->

  # Generate a cert and key in Java keystore for the server itself.
  exec { "server_keystore":
    command => "keytool -keystore ${ssl_dir}/${::hostname}.keystore.jks -storepass ${ssl_keystore_password} -keypass ${ssl_keystore_password} -genkey -dname \"CN=${::fqdn}, OU=Kafka, O=Kafka, L=Kafka, S=Kafka, C=US\" -alias localhost -validity ${ssl_validity_days} -ext SAN=DNS:${::fqdn}",
    creates => "${ssl_dir}/${::hostname}.keystore.jks",
  } ->

  # Get the CSR out of the keystore, so we can sign it and then import the signed
  # certificate and the CA cert into the keystore.
  exec { "server_keystore_get_csr":
    command => "keytool -keystore ${ssl_dir}/${::hostname}.keystore.jks -storepass ${ssl_keystore_password} -keypass ${ssl_keystore_password} -certreq -alias localhost -file ${ssl_dir}/${::hostname}.csr",
    creates => "${ssl_dir}/${::hostname}.csr",
  } ->

  exec { "server_keystore_sign_cert":
    command => "openssl x509 -req -CA ${ssl_dir}/ca.crt  -CAkey ${ssl_dir}/ca.key -in ${ssl_dir}/${::hostname}.csr -out ${ssl_dir}/${::hostname}.signed.crt -days ${ssl_validity_days} -CAcreateserial",
    creates => "${ssl_dir}/${::hostname}.signed.crt",
  }


  # If a new server keystore is created, import the CA cert into it.
  exec { "server_keystore_import_ca_cert":
    command     => "keytool -keystore ${ssl_dir}/${::hostname}.keystore.jks -storepass ${ssl_keystore_password} -keypass ${ssl_keystore_password} -alias CARoot -import -file ${ssl_dir}/ca.crt -noprompt",
    subscribe   => Exec["server_keystore"],
    refreshonly => true,
  }

  # Once the server cert has been signed, import the signed cert into the Java keystore.
  exec { "server_keystore_import_signed_cert":
    command     => "keytool -keystore ${ssl_dir}/${::hostname}.keystore.jks -storepass ${ssl_keystore_password} -keypass ${ssl_keystore_password} -alias localhost -import -file ${ssl_dir}/${::hostname}.signed.crt -noprompt",
    subscribe   => Exec['server_keystore_sign_cert'],
    refreshonly => true,

    # Import fails if we haven't already imported the CA cert.
    require     => Exec['server_keystore_import_ca_cert'],
  }


  # If anything in this class changes, notify the Kafka service.
  Class['::kafka::ssl::broker'] ~> Class['::kafka::broker::service']

}
